#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::keyboard::input_source::{change_input_source, get_cur_session_input_source};
#[cfg(target_os = "linux")]
use crate::platform::linux::is_x11;
use crate::{
    client::file_trait::FileManager,
    common::{
        make_fd_to_json, make_vec_fd_to_json, strict_http_request_blocking,
        strict_http_request_no_bearer_blocking, RequestSecurityClass, StrictHttpMethod,
        StrictHttpRequest,
    },
    flutter::{
        self, session_add, session_add_existed, session_start_, sessions, try_sync_peer_option,
    },
    hbbs_http::{
        auth_binding::{
            self, AuthAttempt, AuthSessionSnapshot, AuthSnapshot, CredentialedRequestHandle,
            DeviceIdentitySnapshot, PersonalHashSource,
        },
        auth_state_store::{AddressBookCapability, AuthAuthorityAnchor, AuthSafeUser},
    },
    input::*,
    ui_interface::{self, *},
};
use flutter_rust_bridge::{StreamSink, SyncReturn};
#[cfg(feature = "plugin_framework")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::allow_err;
use hbb_common::{
    anyhow::{self, anyhow},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{self, LocalConfig, PeerConfig, PeerInfoSerde},
    fs, lazy_static, log,
    rendezvous_proto::ConnType,
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

pub type SessionID = uuid::Uuid;

lazy_static::lazy_static! {
    static ref TEXTURE_RENDER_KEY: Arc<AtomicI32> = Arc::new(AtomicI32::new(0));
    static ref AUTH_CACHE_IO_LOCK: Mutex<()> = Mutex::new(());
}

static FLUTTER_AUTH_APP_DIR: OnceLock<PathBuf> = OnceLock::new();

const ISSUE9_MAX_FFI_JSON_BYTES: usize = 16 * 1024 * 1024;
const ISSUE9_MAX_CACHE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const ISSUE9_MAX_LOGIN_BODY_BYTES: usize = 64 * 1024;
const ISSUE9_MAX_AUTH_ATTEMPT_BYTES: usize = 8 * 1024;
const ISSUE9_MAX_HEADER_COUNT: usize = 32;
const ISSUE9_MAX_HEADER_BYTES: usize = 64 * 1024;
const ISSUE9_MAX_SAFE_TEXT_BYTES: usize = 16 * 1024;
const ISSUE9_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const ISSUE9_MAX_PERSONAL_HASH_ENTRIES: usize = 100_000;
const ISSUE9_MAX_ENCODED_PERSONAL_HASH_BYTES: usize = 2 * 1024;
const ISSUE9_MAX_DECODED_PERSONAL_HASH_BYTES: usize = 1024;

#[derive(Clone, Deserialize, Serialize)]
struct FfiCredentialedRequest {
    #[serde(flatten)]
    handle: CredentialedRequestHandle,
    cursor: u64,
    capability: AddressBookCapability,
    force_full_pending: bool,
}

#[derive(Serialize)]
struct FfiStrictHttpResponse {
    request_id: String,
    status: u16,
    content_type: Option<String>,
    retry_after: Option<String>,
    body: String,
    normalized_api_base: String,
    namespace: String,
    session_epoch: u64,
    session_nonce: String,
    cursor_key: String,
    cursor: u64,
    personal_hash_receipt: Option<String>,
}

fn protected_auth_bridge_key(key: &str) -> bool {
    auth_binding::is_protected_auth_option(key)
}

fn protected_generic_write_key(key: &str) -> bool {
    !ui_interface::option_bridge_allows_write_key(key)
}

fn filter_protected_options(raw: String) -> String {
    let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(&raw) else {
        return "{}".to_owned();
    };
    map.retain(|key, _| !protected_auth_bridge_key(key));
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_owned())
}

fn auth_safe_user_ui_value(user: &AuthSafeUser) -> Value {
    json!({
        "id": user.id,
        "name": user.name,
        "display_name": user.display_name,
        "avatar": user.avatar,
        "email": user.email,
        "note": user.note,
        "status": user.status,
        "is_admin": user.is_admin,
    })
}

fn serialize_auth_snapshot(snapshot: &AuthSnapshot) -> ResultType<String> {
    let mut value =
        serde_json::to_value(snapshot).map_err(|_| anyhow!("无法序列化安全认证状态"))?;
    if let Some(safe_user) = value
        .get_mut("session")
        .and_then(Value::as_object_mut)
        .and_then(|session| session.get_mut("safe_user"))
    {
        *safe_user = match snapshot.session.as_ref() {
            Some(session) => auth_safe_user_ui_value(&session.safe_user),
            None => Value::Null,
        };
    }
    serde_json::to_string(&value).map_err(|_| anyhow!("无法序列化安全认证状态"))
}

fn sanitize_current_user_response(body: &str) -> ResultType<String> {
    let value = serde_json::from_str::<Value>(body).map_err(|_| anyhow!("当前用户响应格式无效"))?;
    let safe_user = parse_safe_auth_user(&value)?;
    serde_json::to_string(&auth_safe_user_ui_value(&safe_user))
        .map_err(|_| anyhow!("无法序列化安全用户信息"))
}

fn parse_credentialed_request(json: &str) -> ResultType<FfiCredentialedRequest> {
    if json.is_empty() || json.len() > ISSUE9_MAX_FFI_JSON_BYTES {
        hbb_common::bail!("认证请求句柄大小无效");
    }
    serde_json::from_str(json).map_err(|_| anyhow!("认证请求句柄格式无效"))
}

#[derive(Clone, Copy)]
enum AuthCacheKind {
    AddressBook,
    Group,
}

impl AuthCacheKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::AddressBook => "ab",
            Self::Group => "group",
        }
    }
}

fn auth_cache_path(kind: AuthCacheKind) -> PathBuf {
    let filename = format!(
        "{}_{}",
        config::APP_NAME.read().unwrap().clone(),
        kind.suffix()
    );
    config::Config::path(filename)
}

fn validate_auth_cache_payload(payload_json: &str, expected_namespace: &str) -> ResultType<()> {
    if payload_json.is_empty() || payload_json.len() > ISSUE9_MAX_FFI_JSON_BYTES {
        hbb_common::bail!("认证缓存负载大小无效");
    }
    if expected_namespace.is_empty() || expected_namespace.len() > ISSUE9_MAX_SAFE_TEXT_BYTES {
        hbb_common::bail!("认证缓存 namespace 无效");
    }
    let Value::Object(payload) =
        serde_json::from_str::<Value>(payload_json).map_err(|_| anyhow!("认证缓存负载格式无效"))?
    else {
        hbb_common::bail!("认证缓存负载必须是JSON对象");
    };
    if payload.get("access_token").is_some() {
        hbb_common::bail!("认证缓存负载包含禁止字段");
    }
    if payload.get("auth_namespace").and_then(Value::as_str) != Some(expected_namespace) {
        hbb_common::bail!("认证缓存 namespace 与请求代次不匹配");
    }
    Ok(())
}

fn store_auth_cache_json(kind: AuthCacheKind, payload_json: &str) -> ResultType<()> {
    if payload_json.is_empty() || payload_json.len() > ISSUE9_MAX_FFI_JSON_BYTES {
        hbb_common::bail!("认证缓存负载大小无效");
    }
    let Value::Object(_) =
        serde_json::from_str::<Value>(payload_json).map_err(|_| anyhow!("认证缓存负载格式无效"))?
    else {
        hbb_common::bail!("认证缓存负载必须是JSON对象");
    };
    let compressed = hbb_common::compress::compress(payload_json.as_bytes());
    if compressed.is_empty() || compressed.len() as u64 > ISSUE9_MAX_CACHE_FILE_BYTES {
        hbb_common::bail!("认证缓存压缩结果无效");
    }
    let encrypted = hbb_common::password_security::symmetric_crypt(&compressed, true)
        .map_err(|_| anyhow!("认证缓存加密失败"))?;
    if encrypted.len() as u64 > ISSUE9_MAX_CACHE_FILE_BYTES {
        hbb_common::bail!("认证缓存密文过大");
    }
    let path = auth_cache_path(kind);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| anyhow!("无法创建认证缓存目录"))?;
    }
    std::fs::write(path, encrypted).map_err(|_| anyhow!("认证缓存写入失败"))
}

fn normalize_auth_cache_json(plain: &[u8]) -> ResultType<String> {
    if plain.is_empty() || plain.len() > ISSUE9_MAX_FFI_JSON_BYTES {
        hbb_common::bail!("认证缓存解压结果无效");
    }
    let mut payload: Value =
        serde_json::from_slice(plain).map_err(|_| anyhow!("认证缓存JSON无效"))?;
    let Value::Object(ref mut object) = payload else {
        hbb_common::bail!("认证缓存必须是JSON对象");
    };
    // 历史缓存的 access_token 可能是真实凭证，绝不能再返回给 Dart。
    object.remove("access_token");
    serde_json::to_string(&payload).map_err(|_| anyhow!("认证缓存序列化失败"))
}

fn load_auth_cache_json(kind: AuthCacheKind) -> ResultType<String> {
    let path = auth_cache_path(kind);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("{}".to_owned());
        }
        Err(_) => hbb_common::bail!("无法读取认证缓存元数据"),
    };
    if metadata.len() == 0 || metadata.len() > ISSUE9_MAX_CACHE_FILE_BYTES {
        hbb_common::bail!("认证缓存文件大小无效");
    }
    let encrypted = std::fs::read(path).map_err(|_| anyhow!("认证缓存读取失败"))?;
    let compressed = hbb_common::password_security::symmetric_crypt(&encrypted, false)
        .map_err(|_| anyhow!("认证缓存解密失败"))?;
    let plain = hbb_common::compress::decompress(&compressed);
    normalize_auth_cache_json(&plain)
}

fn clear_auth_cache_if_namespace(
    kind: AuthCacheKind,
    expected_namespace: &str,
) -> ResultType<bool> {
    if expected_namespace.is_empty() || expected_namespace.len() > ISSUE9_MAX_SAFE_TEXT_BYTES {
        hbb_common::bail!("认证缓存 namespace 无效");
    }
    let raw = match load_auth_cache_json(kind) {
        Ok(raw) => raw,
        Err(_) => return Ok(false),
    };
    let payload: Value = serde_json::from_str(&raw).map_err(|_| anyhow!("认证缓存JSON无效"))?;
    if payload.get("auth_namespace").and_then(Value::as_str) != Some(expected_namespace) {
        return Ok(false);
    }
    match std::fs::remove_file(auth_cache_path(kind)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => hbb_common::bail!("认证缓存删除失败"),
    }
}

fn parse_personal_hash_peer_items(value: &Value) -> ResultType<Vec<(String, Option<Vec<u8>>)>> {
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("个人地址簿 peers 必须是数组"))?;
    if items.len() > ISSUE9_MAX_PERSONAL_HASH_ENTRIES {
        hbb_common::bail!("个人地址簿 peers 条目过多");
    }
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| anyhow!("个人地址簿 peer 必须是对象"))?;
        let device_id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| {
                !id.is_empty() && id.chars().count() <= 100 && !id.chars().any(char::is_control)
            })
            .ok_or_else(|| anyhow!("个人地址簿设备标识无效"))?
            .to_owned();
        let encoded = match object.get("hash") {
            None | Some(Value::Null) => "",
            Some(Value::String(value)) => value.as_str(),
            Some(_) => hbb_common::bail!("个人地址簿 hash 必须是字符串或 null"),
        };
        let hash = if encoded.is_empty() {
            None
        } else {
            if encoded.len() > ISSUE9_MAX_ENCODED_PERSONAL_HASH_BYTES {
                hbb_common::bail!("个人地址簿 hash 大小无效");
            }
            let decoded = STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| anyhow!("个人地址簿 hash 编码无效"))?;
            if decoded.is_empty() || decoded.len() > ISSUE9_MAX_DECODED_PERSONAL_HASH_BYTES {
                hbb_common::bail!("个人地址簿 hash 大小无效");
            }
            Some(decoded)
        };
        parsed.push((device_id, hash));
    }
    Ok(parsed)
}

fn parse_commercial_personal_page_query(target: &str) -> ResultType<(String, usize, usize)> {
    fn parse_positive_decimal(value: &str, field: &str) -> ResultType<usize> {
        if value.is_empty() || value.len() > 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            hbb_common::bail!("商业个人地址簿{field}无效");
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| anyhow!("商业个人地址簿{field}无效"))?;
        if parsed == 0 || parsed > ISSUE9_MAX_PERSONAL_HASH_ENTRIES {
            hbb_common::bail!("商业个人地址簿{field}无效");
        }
        Ok(parsed)
    }

    let url = Url::parse(target).map_err(|_| anyhow!("商业个人地址簿目标无效"))?;
    let mut guid = None;
    let mut page = None;
    let mut page_size = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "ab" if guid.is_none() => {
                let value = value.into_owned();
                if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                    hbb_common::bail!("商业个人地址簿 guid 无效");
                }
                guid = Some(value);
            }
            "current" if page.is_none() => {
                page = Some(parse_positive_decimal(&value, "页码")?);
            }
            "pageSize" if page_size.is_none() => {
                page_size = Some(parse_positive_decimal(&value, "分页大小")?);
            }
            "ab" | "current" | "pageSize" => {
                hbb_common::bail!("商业个人地址簿分页参数重复");
            }
            _ => hbb_common::bail!("商业个人地址簿包含未知分页参数"),
        }
    }
    Ok((
        guid.ok_or_else(|| anyhow!("商业个人地址簿缺少 guid"))?,
        page.ok_or_else(|| anyhow!("商业个人地址簿缺少页码"))?,
        page_size.ok_or_else(|| anyhow!("商业个人地址簿缺少分页大小"))?,
    ))
}

trait PersonalHashAuthority {
    fn response_is_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> bool;

    fn invalidate_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> ResultType<bool>;

    fn register_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: String,
    ) -> ResultType<bool>;

    fn is_current_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
    ) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn observe_commercial_page(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
        page: usize,
        page_size: usize,
        total: usize,
        items: Vec<(String, Option<Vec<u8>>)>,
    ) -> ResultType<Option<String>>;

    fn issue_receipt(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> ResultType<Option<String>>;
}

struct MainUiPersonalHashAuthority;

impl PersonalHashAuthority for MainUiPersonalHashAuthority {
    fn response_is_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> bool {
        auth_binding::personal_hash_response_is_current(handle, request_fence)
    }

    fn invalidate_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> ResultType<bool> {
        auth_binding::invalidate_personal_hash_provenance_if_current(handle, request_fence)
    }

    fn register_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: String,
    ) -> ResultType<bool> {
        auth_binding::register_commercial_personal_guid(handle, request_fence, guid)
    }

    fn is_current_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
    ) -> bool {
        auth_binding::is_current_commercial_personal_guid(handle, request_fence, guid)
    }

    fn observe_commercial_page(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
        page: usize,
        page_size: usize,
        total: usize,
        items: Vec<(String, Option<Vec<u8>>)>,
    ) -> ResultType<Option<String>> {
        auth_binding::observe_commercial_personal_hash_page(
            handle,
            request_fence,
            guid,
            page,
            page_size,
            total,
            items,
        )
    }

    fn issue_receipt(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> ResultType<Option<String>> {
        auth_binding::issue_personal_hash_receipt(handle, request_fence, source, hashes)
    }
}

#[cfg(test)]
impl PersonalHashAuthority for auth_binding::AuthBinding {
    fn response_is_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> bool {
        self.personal_hash_response_is_current(handle, request_fence)
    }

    fn invalidate_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> ResultType<bool> {
        self.invalidate_personal_hash_provenance_if_current(handle, request_fence)
    }

    fn register_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: String,
    ) -> ResultType<bool> {
        self.register_commercial_personal_guid(handle, request_fence, guid)
    }

    fn is_current_commercial_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
    ) -> bool {
        self.is_current_commercial_personal_guid(handle, request_fence, guid)
    }

    fn observe_commercial_page(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
        page: usize,
        page_size: usize,
        total: usize,
        items: Vec<(String, Option<Vec<u8>>)>,
    ) -> ResultType<Option<String>> {
        self.observe_commercial_personal_hash_page(
            handle,
            request_fence,
            guid,
            page,
            page_size,
            total,
            items,
        )
    }

    fn issue_receipt(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> ResultType<Option<String>> {
        self.issue_personal_hash_receipt(handle, request_fence, source, hashes)
    }
}

fn observe_native_personal_hash_response(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    operation: FfiSessionOperation,
    target: &str,
    status: u16,
    content_type: Option<&str>,
    body: &str,
) -> ResultType<Option<String>> {
    observe_native_personal_hash_response_with(
        &mut MainUiPersonalHashAuthority,
        handle,
        request_fence,
        operation,
        target,
        status,
        content_type,
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_native_personal_hash_response_with(
    authority: &mut impl PersonalHashAuthority,
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    operation: FfiSessionOperation,
    target: &str,
    status: u16,
    content_type: Option<&str>,
    body: &str,
) -> ResultType<Option<String>> {
    // 必须先检查请求开始时捕获的原生栅栏。迟到响应不得解析，更不得清空新代状态。
    if !authority.response_is_current(handle, request_fence) {
        return Ok(None);
    }
    let is_json = content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    let path = relative_session_path(&handle.normalized_api_base, target)?;
    if operation == FfiSessionOperation::AddressBookCommercial && path == "/api/ab/personal" {
        if status != 200 {
            authority.invalidate_if_current(handle, request_fence)?;
            return Ok(None);
        }
        if !is_json {
            authority.invalidate_if_current(handle, request_fence)?;
            hbb_common::bail!("商业个人地址簿响应 Content-Type 无效");
        }
        let result = (|| {
            let value: Value =
                serde_json::from_str(body).map_err(|_| anyhow!("商业个人地址簿响应无效"))?;
            let guid = value
                .get("guid")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|guid| !guid.is_empty())
                .ok_or_else(|| anyhow!("商业个人地址簿响应缺少 guid"))?;
            if !authority.register_commercial_guid(handle, request_fence, guid.to_owned())? {
                hbb_common::bail!("商业个人地址簿请求已失效");
            }
            Ok(None)
        })();
        if result.is_err() {
            authority.invalidate_if_current(handle, request_fence)?;
        }
        return result;
    }

    if operation == FfiSessionOperation::AddressBookCommercial && path == "/api/ab/peers" {
        let (guid, page, page_size) = match parse_commercial_personal_page_query(target) {
            Ok(query) => query,
            Err(error) => {
                authority.invalidate_if_current(handle, request_fence)?;
                return Err(error);
            }
        };
        if !authority.is_current_commercial_guid(handle, request_fence, &guid) {
            return Ok(None);
        }
        if status != 200 {
            authority.invalidate_if_current(handle, request_fence)?;
            return Ok(None);
        }
        if !is_json {
            authority.invalidate_if_current(handle, request_fence)?;
            hbb_common::bail!("商业个人地址簿分页响应 Content-Type 无效");
        }
        let result = (|| {
            let value: Value =
                serde_json::from_str(body).map_err(|_| anyhow!("商业个人地址簿分页响应无效"))?;
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("商业个人地址簿分页响应必须是对象"))?;
            let total = object
                .get("total")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| anyhow!("商业个人地址簿 total 无效"))?;
            let data = object
                .get("data")
                .ok_or_else(|| anyhow!("商业个人地址簿响应缺少 data"))?;
            let items = parse_personal_hash_peer_items(data)?;
            authority.observe_commercial_page(
                handle,
                request_fence,
                &guid,
                page,
                page_size,
                total,
                items,
            )
        })();
        if result.is_err() {
            authority.invalidate_if_current(handle, request_fence)?;
        }
        return result;
    }

    if operation != FfiSessionOperation::AddressBookRead || path != "/api/ab" {
        return Ok(None);
    }
    if status != 200 {
        authority.invalidate_if_current(handle, request_fence)?;
        return Ok(None);
    }
    if !is_json {
        authority.invalidate_if_current(handle, request_fence)?;
        hbb_common::bail!("legacy 地址簿响应 Content-Type 无效");
    }
    let result = (|| {
        let trimmed = body.trim();
        if trimmed == "null" {
            return authority.issue_receipt(
                handle,
                request_fence,
                PersonalHashSource::LegacyPersonal,
                BTreeMap::new(),
            );
        }
        let value: Value =
            serde_json::from_str(trimmed).map_err(|_| anyhow!("legacy 地址簿响应无效"))?;
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("legacy 地址簿响应必须是对象"))?;
        if object.contains_key("mode")
            || object.contains_key("ab_ver")
            || object.contains_key("writable")
        {
            authority.invalidate_if_current(handle, request_fence)?;
            return Ok(None);
        }
        let data = object
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legacy 地址簿响应缺少 data"))?;
        let payload: Value =
            serde_json::from_str(data).map_err(|_| anyhow!("legacy 地址簿 data 无效"))?;
        if payload.is_null() {
            return authority.issue_receipt(
                handle,
                request_fence,
                PersonalHashSource::LegacyPersonal,
                BTreeMap::new(),
            );
        }
        let peers = payload
            .get("peers")
            .ok_or_else(|| anyhow!("legacy 地址簿 data 缺少 peers"))?;
        let items = parse_personal_hash_peer_items(peers)?;
        let mut hashes = BTreeMap::new();
        let mut seen = HashSet::with_capacity(items.len());
        for (device_id, hash) in items {
            if !seen.insert(device_id.clone()) {
                hbb_common::bail!("legacy 地址簿包含重复设备");
            }
            if let Some(hash) = hash {
                hashes.insert(device_id, hash);
            }
        }
        authority.issue_receipt(
            handle,
            request_fence,
            PersonalHashSource::LegacyPersonal,
            hashes,
        )
    })();
    if result.is_err() {
        authority.invalidate_if_current(handle, request_fence)?;
    }
    result
}

fn session_for_handle(handle: &CredentialedRequestHandle) -> ResultType<AuthSessionSnapshot> {
    if !auth_binding::is_request_current(handle) {
        hbb_common::bail!("认证请求句柄已失效");
    }
    let session = auth_binding::auth_snapshot()?
        .session
        .ok_or_else(|| anyhow!("当前没有有效认证会话"))?;
    if session.normalized_api_base != handle.normalized_api_base
        || session.namespace != handle.namespace
        || session.cursor_key != handle.cursor_key
        || session.session_epoch != handle.session_epoch
        || session.session_nonce != handle.session_nonce
    {
        hbb_common::bail!("认证请求句柄与当前会话不匹配");
    }
    Ok(session)
}

fn request_envelope(
    handle: CredentialedRequestHandle,
    session: AuthSessionSnapshot,
) -> FfiCredentialedRequest {
    FfiCredentialedRequest {
        handle,
        cursor: session.cursor,
        capability: session.capability,
        force_full_pending: session.force_full_pending,
    }
}

fn parse_strict_method(method: &str) -> ResultType<StrictHttpMethod> {
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(StrictHttpMethod::Get),
        "POST" => Ok(StrictHttpMethod::Post),
        "PUT" => Ok(StrictHttpMethod::Put),
        "DELETE" => Ok(StrictHttpMethod::Delete),
        "PATCH" => Ok(StrictHttpMethod::Patch),
        _ => hbb_common::bail!("不支持的严格HTTP方法"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FfiSessionOperation {
    CurrentUser,
    DeviceGroups,
    Users,
    Peers,
    AddressBookRead,
    AddressBookWrite,
    AddressBookCommercial,
    Sysinfo,
}

fn relative_session_path(normalized_base: &str, target: &str) -> ResultType<String> {
    auth_binding::validate_target_against_base(normalized_base, target)?;
    let base = Url::parse(normalized_base).map_err(|_| anyhow!("权威API地址无效"))?;
    let target = Url::parse(target).map_err(|_| anyhow!("严格HTTP目标地址无效"))?;
    let base_path = base.path().trim_end_matches('/');
    if base_path.is_empty() {
        return Ok(target.path().to_owned());
    }
    let remaining = target
        .path()
        .strip_prefix(base_path)
        .ok_or_else(|| anyhow!("严格HTTP目标路径不属于权威API地址"))?;
    if remaining.is_empty() {
        Ok("/".to_owned())
    } else if remaining.starts_with('/') {
        Ok(remaining.to_owned())
    } else {
        hbb_common::bail!("严格HTTP目标路径边界无效");
    }
}

fn has_safe_path_argument(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|argument| {
        !argument.is_empty()
            && argument.len() <= 512
            && argument
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
    })
}

/// 将通用 FFI 参数收敛为客户端实际使用的业务操作；认证、注销、OIDC 等端点必须走专用桥。
fn classify_session_operation(
    method: StrictHttpMethod,
    target: &str,
    normalized_base: &str,
) -> ResultType<FfiSessionOperation> {
    let path = relative_session_path(normalized_base, target)?;
    let operation = match (method, path.as_str()) {
        (StrictHttpMethod::Post, "/api/currentUser") => FfiSessionOperation::CurrentUser,
        (StrictHttpMethod::Get, "/api/device-group/accessible") => {
            FfiSessionOperation::DeviceGroups
        }
        (StrictHttpMethod::Get, "/api/users") => FfiSessionOperation::Users,
        (StrictHttpMethod::Get, "/api/peers") => FfiSessionOperation::Peers,
        (StrictHttpMethod::Get, "/api/ab") => FfiSessionOperation::AddressBookRead,
        (StrictHttpMethod::Post, "/api/ab") => FfiSessionOperation::AddressBookWrite,
        (StrictHttpMethod::Post, "/api/ab/settings")
        | (StrictHttpMethod::Post, "/api/ab/personal")
        | (StrictHttpMethod::Post, "/api/ab/shared/profiles")
        | (StrictHttpMethod::Post, "/api/ab/peers") => FfiSessionOperation::AddressBookCommercial,
        (StrictHttpMethod::Post, "/api/sysinfo") => FfiSessionOperation::Sysinfo,
        (StrictHttpMethod::Post, path)
            if has_safe_path_argument(path, "/api/ab/tags/")
                || has_safe_path_argument(path, "/api/ab/peer/add/")
                || has_safe_path_argument(path, "/api/ab/tag/add/") =>
        {
            FfiSessionOperation::AddressBookCommercial
        }
        (StrictHttpMethod::Put, path)
            if has_safe_path_argument(path, "/api/ab/peer/update/")
                || has_safe_path_argument(path, "/api/ab/tag/rename/")
                || has_safe_path_argument(path, "/api/ab/tag/update/") =>
        {
            FfiSessionOperation::AddressBookCommercial
        }
        (StrictHttpMethod::Delete, path)
            if has_safe_path_argument(path, "/api/ab/peer/")
                || has_safe_path_argument(path, "/api/ab/tag/") =>
        {
            FfiSessionOperation::AddressBookCommercial
        }
        _ => hbb_common::bail!("该会话业务端点或HTTP方法不在native白名单中"),
    };
    Ok(operation)
}

fn commercial_address_book_mutation_guid(
    method: StrictHttpMethod,
    target: &str,
    normalized_base: &str,
) -> ResultType<Option<String>> {
    let path = relative_session_path(normalized_base, target)?;
    let prefix = match method {
        StrictHttpMethod::Post if path.starts_with("/api/ab/peer/add/") => "/api/ab/peer/add/",
        StrictHttpMethod::Put if path.starts_with("/api/ab/peer/update/") => "/api/ab/peer/update/",
        StrictHttpMethod::Delete if path.starts_with("/api/ab/peer/") => "/api/ab/peer/",
        _ => return Ok(None),
    };
    let guid = path
        .strip_prefix(prefix)
        .filter(|value| has_safe_path_argument(&path, prefix) && !value.is_empty())
        .ok_or_else(|| anyhow!("商业地址簿 mutation GUID 无效"))?;
    Ok(Some(guid.to_owned()))
}

fn parse_strict_headers(json: &str) -> ResultType<Vec<(String, String)>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    if json.len() > ISSUE9_MAX_HEADER_BYTES {
        hbb_common::bail!("严格HTTP请求头过大");
    }
    let Value::Object(map) =
        serde_json::from_str::<Value>(json).map_err(|_| anyhow!("严格HTTP请求头格式无效"))?
    else {
        hbb_common::bail!("严格HTTP请求头必须是JSON对象");
    };
    if map.len() > ISSUE9_MAX_HEADER_COUNT {
        hbb_common::bail!("严格HTTP请求头数量过多");
    }
    let mut headers = Vec::with_capacity(map.len());
    for (name, value) in map {
        let Value::String(value) = value else {
            hbb_common::bail!("严格HTTP请求头值必须是字符串");
        };
        let normalized_name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 256
            || value.len() > 16 * 1024
            || name.chars().any(char::is_control)
            || value.chars().any(char::is_control)
            || matches!(
                normalized_name.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
                    | "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
            )
        {
            hbb_common::bail!("Dart不得提供凭证或目标主机请求头");
        }
        headers.push((name, value));
    }
    Ok(headers)
}

fn endpoint_from_base(base: &str, suffix: &str) -> ResultType<String> {
    let mut url = Url::parse(base).map_err(|_| anyhow!("API地址无效"))?;
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/{}", suffix.trim_start_matches('/')));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn flutter_auth_authority_anchor(package_identity: &str) -> ResultType<AuthAuthorityAnchor> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let package_identity = package_identity.trim();
        if package_identity.is_empty()
            || package_identity.len() > 512
            || package_identity.chars().any(char::is_control)
        {
            hbb_common::bail!("移动端package或bundle identity无效");
        }
        let app_dir = FLUTTER_AUTH_APP_DIR
            .get()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| anyhow!("移动端认证根目录尚未冻结"))?;
        return AuthAuthorityAnchor::from_root_and_identity(
            app_dir.join(".rustdesk").join("ui_auth_v1"),
            package_identity.as_bytes(),
        );
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = package_identity;
        AuthAuthorityAnchor::for_current_install()
    }
}

fn current_flutter_device_identity() -> DeviceIdentitySnapshot {
    let id = ui_interface::get_id();
    let uuid = ui_interface::get_uuid();
    let valid = !id.is_empty()
        && !uuid.is_empty()
        && id.chars().count() <= 100
        && !id.chars().any(char::is_control)
        && uuid.len() <= 512
        && !uuid.chars().any(char::is_control);
    if valid {
        DeviceIdentitySnapshot { id, uuid }
    } else {
        DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        }
    }
}

fn safe_user_text(user: &serde_json::Map<String, Value>, key: &str) -> ResultType<String> {
    match user.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) if value.len() <= ISSUE9_MAX_SAFE_TEXT_BYTES => {
            Ok(value.clone())
        }
        Some(Value::String(_)) => hbb_common::bail!("登录响应中的用户字段过长"),
        Some(_) => hbb_common::bail!("登录响应中的用户字段类型无效"),
    }
}

fn parse_safe_auth_user(value: &Value) -> ResultType<AuthSafeUser> {
    let Value::Object(user) = value else {
        hbb_common::bail!("登录响应缺少安全用户信息");
    };
    let id = match user.get("id") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let id = value
                .as_u64()
                .ok_or_else(|| anyhow!("登录响应中的用户ID无效"))?;
            if id == 0 || id > ISSUE9_MAX_SAFE_INTEGER {
                hbb_common::bail!("登录响应中的用户ID超出安全整数范围");
            }
            Some(id)
        }
    };
    let name = safe_user_text(user, "name")?;
    if name.is_empty() || name.chars().any(char::is_control) {
        hbb_common::bail!("登录响应中的用户名无效");
    }
    let status = match user.get("status") {
        None | Some(Value::Null) => 1,
        Some(value) => value
            .as_i64()
            .ok_or_else(|| anyhow!("登录响应中的用户状态无效"))?,
    };
    let is_admin = match user.get("is_admin") {
        None | Some(Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow!("登录响应中的管理员标记无效"))?,
    };
    Ok(AuthSafeUser {
        id,
        name,
        display_name: safe_user_text(user, "display_name")?,
        avatar: safe_user_text(user, "avatar")?,
        email: safe_user_text(user, "email")?,
        note: safe_user_text(user, "note")?,
        status,
        is_admin,
        verifier: safe_user_text(user, "verifier")?,
    })
}

fn login_expiry_hint(body: &serde_json::Map<String, Value>) -> Option<i64> {
    if let Some(expires_at) = body.get("expires_at").and_then(Value::as_i64) {
        return (expires_at > 0).then_some(expires_at);
    }
    let expires_in = body.get("expires_in").and_then(Value::as_i64)?;
    if expires_in <= 0 {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let expires_at = now.checked_add(expires_in as u64)?;
    i64::try_from(expires_at).ok()
}

fn serialize_login_challenge(
    body: &serde_json::Map<String, Value>,
    status: u16,
    opaque_attempt: &str,
) -> ResultType<String> {
    let response_type = safe_user_text(body, "type")?;
    let tfa_type = safe_user_text(body, "tfa_type")?;
    let challenge_type = if response_type.is_empty() {
        tfa_type.clone()
    } else {
        response_type.clone()
    };
    if challenge_type.is_empty() {
        hbb_common::bail!("登录响应既不是认证成功也不是有效挑战");
    }
    let secret = safe_user_text(body, "secret")?;
    let user = body
        .get("user")
        .filter(|value| !value.is_null())
        .map(parse_safe_auth_user)
        .transpose()?;
    let user = user.as_ref().map(auth_safe_user_ui_value);
    Ok(json!({
        "kind": "challenge",
        "status": status,
        "challenge_type": challenge_type,
        "type": response_type,
        "tfa_type": tfa_type,
        "secret": secret,
        "user": user,
        "native_attempt": opaque_attempt,
    })
    .to_string())
}

fn contains_native_reserved_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            key.to_ascii_lowercase().starts_with("native_") || contains_native_reserved_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_native_reserved_field),
        _ => false,
    }
}

fn validate_and_normalize_login_body(login_body: &str) -> ResultType<String> {
    if login_body.is_empty() || login_body.len() > ISSUE9_MAX_LOGIN_BODY_BYTES {
        hbb_common::bail!("登录请求体大小无效");
    }
    let value =
        serde_json::from_str::<Value>(login_body).map_err(|_| anyhow!("登录请求体格式无效"))?;
    let Value::Object(_) = &value else {
        hbb_common::bail!("登录请求体必须是JSON对象");
    };
    if contains_native_reserved_field(&value) {
        hbb_common::bail!("登录请求体包含 native 保留字段");
    }
    serde_json::to_string(&value).map_err(|_| anyhow!("无法规范化登录请求体"))
}

fn serialize_login_outcome_if_current(attempt: &AuthAttempt, outcome: Value) -> ResultType<String> {
    if !auth_binding::is_auth_attempt_current(attempt) {
        hbb_common::bail!("登录请求已失效");
    }
    Ok(outcome.to_string())
}

fn initialize(app_dir: &str, custom_client_config: &str) {
    flutter::async_tasks::start_flutter_async_runner();
    // `APP_DIR` is set in `main_get_data_dir_ios()` on iOS.
    #[cfg(not(target_os = "ios"))]
    {
        *config::APP_DIR.write().unwrap() = app_dir.to_owned();
    }
    // core_main's load_custom_client does not work for flutter since it is only applied to its load_library in main.c
    if custom_client_config.is_empty() {
        crate::load_custom_client();
    } else {
        crate::read_custom_client(custom_client_config);
    }
    #[cfg(target_os = "android")]
    {
        // flexi_logger can't work when android_logger initialized.
        #[cfg(debug_assertions)]
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug) // limit log level
                .with_tag("ffi"), // logs will show under mytag tag
        );
        #[cfg(not(debug_assertions))]
        hbb_common::init_log(false, "");
        #[cfg(feature = "mediacodec")]
        scrap::mediacodec::check_mediacodec();
        crate::common::test_rendezvous_server();
        crate::common::test_nat_type();
    }
    #[cfg(target_os = "ios")]
    {
        use hbb_common::env_logger::*;
        init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
        crate::common::test_nat_type();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = crate::common::global_init();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        // core_main's init_log does not work for flutter since it is only applied to its load_library in main.c
        hbb_common::init_log(false, "flutter_ffi");
    }
}

#[inline]
pub fn start_global_event_stream(s: StreamSink<String>, app_type: String) -> ResultType<()> {
    let is_main = app_type
        .split(',')
        .next()
        .is_some_and(|value| value == flutter::APP_TYPE_MAIN);
    super::flutter::start_global_event_stream(s, app_type)?;
    if is_main && auth_binding::is_main_ui_auth_initialized() {
        crate::hbbs_http::address_book_sync::ensure_worker_started();
        crate::hbbs_http::address_book_sync::wake_worker();
    }
    Ok(())
}

#[inline]
pub fn stop_global_event_stream(app_type: String) {
    super::flutter::stop_global_event_stream(app_type)
}
pub enum EventToUI {
    Event(String),
    Rgba(usize),
    Texture(usize, bool), // (display, gpu_texture)
}

pub fn host_stop_system_key_propagate(_stopped: bool) {
    #[cfg(windows)]
    crate::platform::windows::stop_system_key_propagate(_stopped);
}

// This function is only used to count the number of control sessions.
pub fn peer_get_sessions_count(id: String, conn_type: i32) -> SyncReturn<usize> {
    let conn_type = if conn_type == ConnType::VIEW_CAMERA as i32 {
        ConnType::VIEW_CAMERA
    } else if conn_type == ConnType::FILE_TRANSFER as i32 {
        ConnType::FILE_TRANSFER
    } else if conn_type == ConnType::PORT_FORWARD as i32 {
        ConnType::PORT_FORWARD
    } else if conn_type == ConnType::RDP as i32 {
        ConnType::RDP
    } else if conn_type == ConnType::TERMINAL as i32 {
        ConnType::TERMINAL
    } else {
        ConnType::DEFAULT_CONN
    };
    SyncReturn(sessions::get_session_count(id, conn_type))
}

pub fn session_add_existed_sync(
    id: String,
    session_id: SessionID,
    displays: Vec<i32>,
    is_view_camera: bool,
) -> SyncReturn<String> {
    if let Err(e) = session_add_existed(id.clone(), session_id, displays, is_view_camera) {
        SyncReturn(format!("Failed to add session with id {}, {}", &id, e))
    } else {
        SyncReturn("".to_owned())
    }
}

pub fn session_add_sync(
    session_id: SessionID,
    id: String,
    is_file_transfer: bool,
    is_view_camera: bool,
    is_port_forward: bool,
    is_rdp: bool,
    is_terminal: bool,
    switch_uuid: String,
    force_relay: bool,
    password: String,
    is_shared_password: bool,
    conn_token: Option<String>,
) -> SyncReturn<String> {
    let add_res = session_add(
        &session_id,
        &id,
        is_file_transfer,
        is_view_camera,
        is_port_forward,
        is_rdp,
        is_terminal,
        &switch_uuid,
        force_relay,
        password,
        is_shared_password,
        conn_token,
    );
    // We can't put the remove call together with `std::env::var("IS_TERMINAL_ADMIN")`.
    // Because there are some `bail!` in `session_add()`, we must make sure `IS_TERMINAL_ADMIN` is removed at last.
    if is_terminal {
        std::env::remove_var("IS_TERMINAL_ADMIN");
    }

    if let Err(e) = add_res {
        SyncReturn(format!("Failed to add session with id {}, {}", &id, e))
    } else {
        SyncReturn("".to_owned())
    }
}

pub fn session_start(
    events2ui: StreamSink<EventToUI>,
    session_id: SessionID,
    id: String,
) -> ResultType<()> {
    session_start_(&session_id, &id, events2ui)
}

pub fn session_start_with_displays(
    events2ui: StreamSink<EventToUI>,
    session_id: SessionID,
    id: String,
    displays: Vec<i32>,
) -> ResultType<()> {
    session_start_(&session_id, &id, events2ui)?;

    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.capture_displays(displays.clone(), vec![], vec![]);
        for display in displays {
            session.refresh_video(display as _);
        }
    }
    Ok(())
}

pub fn session_get_remember(session_id: SessionID) -> Option<bool> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_remember())
    } else {
        None
    }
}

pub fn session_get_toggle_option(session_id: SessionID, arg: String) -> Option<bool> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_toggle_option(arg))
    } else {
        None
    }
}

pub fn session_get_toggle_option_sync(session_id: SessionID, arg: String) -> SyncReturn<bool> {
    let res = session_get_toggle_option(session_id, arg) == Some(true);
    SyncReturn(res)
}

pub fn session_get_option(session_id: SessionID, arg: String) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_option(arg))
    } else {
        None
    }
}

pub fn session_login(
    session_id: SessionID,
    os_username: String,
    os_password: String,
    password: String,
    remember: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.login(os_username, os_password, password, remember);
    }
}

pub fn session_send2fa(session_id: SessionID, code: String, trust_this_device: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.send2fa(code, trust_this_device);
    }
}

pub fn session_get_enable_trusted_devices(session_id: SessionID) -> SyncReturn<bool> {
    let v = if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.get_enable_trusted_devices()
    } else {
        false
    };
    SyncReturn(v)
}

pub fn will_session_close_close_session(session_id: SessionID) -> SyncReturn<bool> {
    SyncReturn(sessions::would_remove_peer_by_session_id(&session_id))
}

pub fn session_close(session_id: SessionID) {
    if let Some(session) = sessions::remove_session_by_session_id(&session_id) {
        // `release_remote_keys` is not required for mobile platforms in common cases.
        // But we still call it to make the code more stable.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        crate::keyboard::release_remote_keys("map");
        session.close_event_stream(session_id);
        session.close();
    }
}

pub fn session_refresh(session_id: SessionID, display: usize) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.refresh_video(display as _);
    }
}

pub fn session_take_screenshot(session_id: SessionID, display: usize) {
    if let Some(s) = sessions::get_session_by_session_id(&session_id) {
        s.take_screenshot(display as _, session_id.to_string());
    }
}

pub fn session_handle_screenshot(
    #[allow(unused_variables)] session_id: SessionID,
    action: String,
) -> String {
    crate::client::screenshot::handle_screenshot(action)
}

pub fn session_is_multi_ui_session(session_id: SessionID) -> SyncReturn<bool> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.is_multi_ui_session())
    } else {
        SyncReturn(false)
    }
}

pub fn session_record_screen(session_id: SessionID, start: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.record_screen(start);
    }
}

pub fn session_get_is_recording(session_id: SessionID) -> SyncReturn<bool> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.is_recording())
    } else {
        SyncReturn(false)
    }
}

pub fn session_reconnect(session_id: SessionID, force_relay: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.reconnect(force_relay);
    }
    session_on_waiting_for_image_dialog_show(session_id);
}

pub fn session_toggle_option(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        log::warn!("toggle option {}", &value);
        session.toggle_option(value.clone());
        try_sync_peer_option(&session, &session_id, &value, None);
    }
    #[cfg(not(target_os = "ios"))]
    if sessions::get_session_by_session_id(&session_id).is_some()
        && (value == "disable-clipboard" || value == "view-only")
    {
        crate::flutter::update_text_clipboard_required();
    }
    #[cfg(feature = "unix-file-copy-paste")]
    if sessions::get_session_by_session_id(&session_id).is_some()
        && (value == config::keys::OPTION_ENABLE_FILE_COPY_PASTE || value == "view-only")
    {
        crate::flutter::update_file_clipboard_required();
    }
}

pub fn session_toggle_privacy_mode(session_id: SessionID, impl_key: String, on: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.toggle_privacy_mode(impl_key, on);
    }
}

pub fn session_get_flutter_option(session_id: SessionID, k: String) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_flutter_option(k))
    } else {
        None
    }
}

pub fn session_set_flutter_option(session_id: SessionID, k: String, v: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_flutter_option(k, v);
    }
}

pub fn get_next_texture_key() -> SyncReturn<i32> {
    let k = TEXTURE_RENDER_KEY.fetch_add(1, Ordering::SeqCst) + 1;
    SyncReturn(k)
}

pub fn get_local_flutter_option(k: String) -> SyncReturn<String> {
    if protected_auth_bridge_key(&k) {
        return SyncReturn(String::new());
    }
    SyncReturn(ui_interface::get_local_flutter_option(k))
}

pub fn set_local_flutter_option(k: String, v: String) {
    if protected_generic_write_key(&k) {
        return;
    }
    ui_interface::set_local_flutter_option(k, v);
}

pub fn get_local_kb_layout_type() -> SyncReturn<String> {
    SyncReturn(ui_interface::get_kb_layout_type())
}

pub fn set_local_kb_layout_type(kb_layout_type: String) {
    ui_interface::set_kb_layout_type(kb_layout_type)
}

pub fn session_get_view_style(session_id: SessionID) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_view_style())
    } else {
        None
    }
}

pub fn session_set_view_style(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_view_style(value);
    }
}

pub fn session_get_scroll_style(session_id: SessionID) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_scroll_style())
    } else {
        None
    }
}

pub fn session_set_scroll_style(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_scroll_style(value);
    }
}

pub fn session_get_edge_scroll_edge_thickness(session_id: SessionID) -> Option<i32> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_edge_scroll_edge_thickness())
    } else {
        None
    }
}

pub fn session_set_edge_scroll_edge_thickness(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_edge_scroll_edge_thickness(value);
    }
}

pub fn session_get_image_quality(session_id: SessionID) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_image_quality())
    } else {
        None
    }
}

pub fn session_set_image_quality(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_image_quality(value);
    }
}

pub fn session_get_keyboard_mode(session_id: SessionID) -> Option<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_keyboard_mode())
    } else {
        None
    }
}

pub fn session_set_keyboard_mode(session_id: SessionID, value: String) {
    let mut _mode_updated = false;
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_keyboard_mode(value.clone());
        _mode_updated = true;
        try_sync_peer_option(&session, &session_id, "keyboard_mode", None);
    }
    #[cfg(windows)]
    if _mode_updated {
        crate::keyboard::update_grab_get_key_name(&value);
    }
}

pub fn session_get_reverse_mouse_wheel_sync(session_id: SessionID) -> SyncReturn<Option<String>> {
    let res = if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_reverse_mouse_wheel())
    } else {
        None
    };
    SyncReturn(res)
}

pub fn session_set_reverse_mouse_wheel(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_reverse_mouse_wheel(value);
    }
}

pub fn session_get_displays_as_individual_windows(
    session_id: SessionID,
) -> SyncReturn<Option<String>> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(Some(session.get_displays_as_individual_windows()))
    } else {
        SyncReturn(None)
    }
}

pub fn session_set_displays_as_individual_windows(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_displays_as_individual_windows(value);
    }
}

pub fn session_get_use_all_my_displays_for_the_remote_session(
    session_id: SessionID,
) -> SyncReturn<Option<String>> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(Some(
            session.get_use_all_my_displays_for_the_remote_session(),
        ))
    } else {
        SyncReturn(None)
    }
}

pub fn session_set_use_all_my_displays_for_the_remote_session(
    session_id: SessionID,
    value: String,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_use_all_my_displays_for_the_remote_session(value);
    }
}

pub fn session_get_custom_image_quality(session_id: SessionID) -> Option<Vec<i32>> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_custom_image_quality())
    } else {
        None
    }
}

pub fn session_is_keyboard_mode_supported(session_id: SessionID, mode: String) -> SyncReturn<bool> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.is_keyboard_mode_supported(mode))
    } else {
        SyncReturn(false)
    }
}

pub fn session_set_custom_image_quality(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_custom_image_quality(value);
    }
}

pub fn session_set_custom_fps(session_id: SessionID, fps: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.set_custom_fps(fps);
    }
}

pub fn session_get_trackpad_speed(session_id: SessionID) -> Option<i32> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        Some(session.get_trackpad_speed())
    } else {
        None
    }
}

pub fn session_set_trackpad_speed(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_trackpad_speed(value);
    }
}

pub fn session_lock_screen(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.lock_screen();
    }
}

pub fn session_ctrl_alt_del(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.ctrl_alt_del();
    }
}

pub fn session_switch_display(is_desktop: bool, session_id: SessionID, value: Vec<i32>) {
    sessions::session_switch_display(is_desktop, session_id, value);
}

pub fn session_handle_flutter_key_event(
    session_id: SessionID,
    character: String,
    usb_hid: i32,
    lock_modes: i32,
    down_or_up: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        let keyboard_mode = session.get_keyboard_mode();
        session.handle_flutter_key_event(
            &keyboard_mode,
            &character,
            usb_hid,
            lock_modes,
            down_or_up,
        );
    }
}

pub fn session_handle_flutter_raw_key_event(
    session_id: SessionID,
    name: String,
    platform_code: i32,
    position_code: i32,
    lock_modes: i32,
    down_or_up: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        let keyboard_mode = session.get_keyboard_mode();
        session.handle_flutter_raw_key_event(
            &keyboard_mode,
            &name,
            platform_code,
            position_code,
            lock_modes,
            down_or_up,
        );
    }
}

// If the cursor jumps between remote page of two connections, leave view and enter view will be called.
// session_enter_or_leave() will be called then.
// As Rust is multi-threaded, enter() can be called before leave().
// The Rust-side grab ownership state filters stale transitions.
pub fn session_enter_or_leave(_session_id: SessionID, _enter: bool) -> SyncReturn<()> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(session) = sessions::get_session_by_session_id(&_session_id) {
        let keyboard_mode = session.get_keyboard_mode();
        // Use the full per-window UUID (not lc.session_id which is per-connection)
        // so that two windows viewing the same peer get distinct grab owners.
        let window_id = _session_id.as_u128();
        if _enter {
            set_cur_session_id_(_session_id, &keyboard_mode);
            crate::keyboard::client::change_grab_status(
                crate::common::GrabState::Run,
                &keyboard_mode,
                window_id,
            );
        } else {
            crate::keyboard::client::change_grab_status(
                crate::common::GrabState::Wait,
                &keyboard_mode,
                window_id,
            );
        }
    }
    SyncReturn(())
}

pub fn session_input_key(
    session_id: SessionID,
    name: String,
    down: bool,
    press: bool,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        // #[cfg(any(target_os = "android", target_os = "ios"))]
        session.input_key(&name, down, press, alt, ctrl, shift, command);
    }
}

pub fn session_input_string(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        // #[cfg(any(target_os = "android", target_os = "ios"))]
        session.input_string(&value);
    }
}

// chat_client_mode
pub fn session_send_chat(session_id: SessionID, text: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.send_chat(text);
    }
}

// Terminal functions
pub fn session_open_terminal(session_id: SessionID, terminal_id: i32, rows: u32, cols: u32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.open_terminal(terminal_id, rows, cols);
    } else {
        log::error!(
            "[flutter_ffi] Session not found for session_id: {}",
            session_id
        );
    }
}

pub fn session_send_terminal_input(session_id: SessionID, terminal_id: i32, data: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.send_terminal_input(terminal_id, data);
    }
}

pub fn session_resize_terminal(session_id: SessionID, terminal_id: i32, rows: u32, cols: u32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.resize_terminal(terminal_id, rows, cols);
    }
}

pub fn session_close_terminal(session_id: SessionID, terminal_id: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.close_terminal(terminal_id);
    }
}

pub fn session_peer_option(session_id: SessionID, name: String, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.set_option(name, value);
    }
}

pub fn session_get_peer_option(session_id: SessionID, name: String) -> String {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        return session.get_option(name);
    }
    "".to_string()
}

pub fn session_input_os_password(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.input_os_password(value, true);
    }
}

// File Action
pub fn session_read_remote_dir(session_id: SessionID, path: String, include_hidden: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.read_remote_dir(path, include_hidden);
    }
}

pub fn session_send_files(
    session_id: SessionID,
    act_id: i32,
    path: String,
    to: String,
    file_num: i32,
    include_hidden: bool,
    is_remote: bool,
    _is_dir: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.send_files(
            act_id,
            fs::JobType::Generic.into(),
            path,
            to,
            file_num,
            include_hidden,
            is_remote,
        );
    }
}

pub fn session_set_confirm_override_file(
    session_id: SessionID,
    act_id: i32,
    file_num: i32,
    need_override: bool,
    remember: bool,
    is_upload: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.set_confirm_override_file(act_id, file_num, need_override, remember, is_upload);
    }
}

pub fn session_remove_file(
    session_id: SessionID,
    act_id: i32,
    path: String,
    file_num: i32,
    is_remote: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.remove_file(act_id, path, file_num, is_remote);
    }
}

pub fn session_read_dir_to_remove_recursive(
    session_id: SessionID,
    act_id: i32,
    path: String,
    is_remote: bool,
    show_hidden: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.remove_dir_all(act_id, path, is_remote, show_hidden);
    }
}

pub fn session_remove_all_empty_dirs(
    session_id: SessionID,
    act_id: i32,
    path: String,
    is_remote: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.remove_dir(act_id, path, is_remote);
    }
}

pub fn session_cancel_job(session_id: SessionID, act_id: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.cancel_job(act_id);
    }
}

pub fn session_create_dir(session_id: SessionID, act_id: i32, path: String, is_remote: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.create_dir(act_id, path, is_remote);
    }
}

pub fn session_read_local_dir_sync(
    _session_id: SessionID,
    path: String,
    show_hidden: bool,
) -> String {
    if let Ok(fd) = fs::read_dir(&fs::get_path(&path), show_hidden) {
        return make_fd_to_json(fd.id, path, &fd.entries);
    }
    "".to_string()
}

pub fn session_read_local_empty_dirs_recursive_sync(
    _session_id: SessionID,
    path: String,
    include_hidden: bool,
) -> String {
    if let Ok(fds) = fs::get_empty_dirs_recursive(&path, include_hidden) {
        return make_vec_fd_to_json(&fds);
    }
    "".to_string()
}

pub fn session_read_remote_empty_dirs_recursive_sync(
    session_id: SessionID,
    path: String,
    include_hidden: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.read_empty_dirs(path, include_hidden);
    }
}

pub fn session_get_platform(session_id: SessionID, is_remote: bool) -> String {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        return session.get_platform(is_remote);
    }
    "".to_string()
}

pub fn session_load_last_transfer_jobs(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        return session.load_last_jobs();
    } else {
        // a tip for flutter dev
        eprintln!(
            "cannot load last transfer job from non-existed session. Please ensure session \
        is connected before calling load last transfer jobs."
        );
    }
}

pub fn session_add_job(
    session_id: SessionID,
    act_id: i32,
    path: String,
    to: String,
    file_num: i32,
    include_hidden: bool,
    is_remote: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.add_job(
            act_id,
            fs::JobType::Generic.into(),
            path,
            to,
            file_num,
            include_hidden,
            is_remote,
        );
    }
}

pub fn session_resume_job(session_id: SessionID, act_id: i32, is_remote: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.resume_job(act_id, is_remote);
    }
}

pub fn session_rename_file(
    session_id: SessionID,
    act_id: i32,
    path: String,
    new_name: String,
    is_remote: bool,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.rename_file(act_id, path, new_name, is_remote);
    }
}

pub fn session_elevate_direct(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.elevate_direct();
    }
}

pub fn session_elevate_with_logon(session_id: SessionID, username: String, password: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.elevate_with_logon(username, password);
    }
}

pub fn session_switch_sides(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.switch_sides();
    }
}

pub fn session_change_resolution(session_id: SessionID, display: i32, width: i32, height: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.change_resolution(display, width, height);
    }
}

pub fn session_set_size(session_id: SessionID, display: usize, width: usize, height: usize) {
    super::flutter::session_set_size(session_id, display, width, height)
}

pub fn session_send_selected_session_id(session_id: SessionID, sid: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.send_selected_session_id(sid);
    }
}

pub fn main_get_sound_inputs() -> Vec<String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return get_sound_inputs();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    vec![String::from("")]
}

pub fn main_get_login_device_info() -> SyncReturn<String> {
    SyncReturn(get_login_device_info_json())
}

pub fn main_change_id(new_id: String) {
    change_id(new_id)
}

pub fn main_get_async_status() -> String {
    get_async_job_status()
}

pub fn main_get_http_status(url: String) -> Option<String> {
    get_async_http_status(url)
}

pub fn main_get_option(key: String) -> String {
    if protected_auth_bridge_key(&key) {
        return String::new();
    }
    get_option(key)
}

pub fn main_get_option_sync(key: String) -> SyncReturn<String> {
    if protected_auth_bridge_key(&key) {
        return SyncReturn(String::new());
    }
    SyncReturn(get_option(key))
}

pub fn main_get_error() -> String {
    get_error()
}

pub fn main_show_option(_key: String) -> SyncReturn<bool> {
    #[cfg(target_os = "linux")]
    if _key.eq(config::keys::OPTION_ALLOW_LINUX_HEADLESS) {
        return SyncReturn(true);
    }
    SyncReturn(false)
}

pub fn main_set_option(key: String, value: String) {
    if protected_generic_write_key(&key) {
        return;
    }
    #[cfg(target_os = "android")]
    {
        let is_permission_option = key.eq(config::keys::OPTION_ENABLE_CLIPBOARD)
            || key.eq(config::keys::OPTION_ENABLE_FILE_TRANSFER)
            || key.eq(config::keys::OPTION_ENABLE_AUDIO);
        let allow_perm_change_in_accept_window = config::option2bool(
            config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW,
            &crate::get_builtin_option(config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW),
        );
        if is_permission_option
            && !allow_perm_change_in_accept_window
            && crate::ui_cm_interface::has_active_clients()
        {
            log::info!(
                "blocked main_set_option by policy, key={}, value={}",
                key,
                value
            );
            return;
        }
    }
    #[cfg(target_os = "android")]
    if key.eq(config::keys::OPTION_ENABLE_KEYBOARD) {
        crate::ui_cm_interface::switch_permission_all(
            "keyboard".to_owned(),
            config::option2bool(&key, &value),
        );
    }
    #[cfg(target_os = "android")]
    if key.eq(config::keys::OPTION_ENABLE_CLIPBOARD) {
        crate::ui_cm_interface::switch_permission_all(
            "clipboard".to_owned(),
            config::option2bool(&key, &value),
        );
    }

    // If `is_allow_tls_fallback` and https proxy is used, we need to restart rendezvous mediator.
    // No need to check if https proxy is used, because this option does not change frequently
    // and restarting mediator is safe even https proxy is not used.
    let is_allow_tls_fallback = key.eq(config::keys::OPTION_ALLOW_INSECURE_TLS_FALLBACK);
    if is_allow_tls_fallback
        || key.eq("custom-rendezvous-server")
        || key.eq(config::keys::OPTION_ALLOW_WEBSOCKET)
        || key.eq(config::keys::OPTION_DISABLE_UDP)
        || key.eq("api-server")
    {
        if is_allow_tls_fallback {
            hbb_common::tls::reset_tls_cache();
        }
        set_option(key, value.clone());
        #[cfg(target_os = "android")]
        crate::rendezvous_mediator::RendezvousMediator::restart();
        #[cfg(any(target_os = "android", target_os = "ios", feature = "cli"))]
        crate::common::test_rendezvous_server();
    } else {
        set_option(key, value.clone());
    }
}

pub fn main_get_options() -> String {
    filter_protected_options(get_options())
}

pub fn main_get_options_sync() -> SyncReturn<String> {
    SyncReturn(filter_protected_options(get_options()))
}

pub fn main_set_options(json: String) {
    let map: HashMap<String, String> = serde_json::from_str(&json).unwrap_or_default();
    if map.keys().any(|key| protected_generic_write_key(key)) {
        return;
    }
    #[cfg(target_os = "android")]
    let mut map = map;
    #[cfg(target_os = "android")]
    {
        let allow_perm_change_in_accept_window = config::option2bool(
            config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW,
            &crate::get_builtin_option(config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW),
        );
        if !allow_perm_change_in_accept_window && crate::ui_cm_interface::has_active_clients() {
            for key in [
                config::keys::OPTION_ENABLE_CLIPBOARD,
                config::keys::OPTION_ENABLE_FILE_TRANSFER,
                config::keys::OPTION_ENABLE_AUDIO,
            ] {
                if let Some(value) = map.remove(key) {
                    log::info!(
                        "blocked main_set_options item by policy, key={}, value={}",
                        key,
                        value
                    );
                }
            }
        }
    }
    if !map.is_empty() {
        set_options(map)
    }
}

/// 四个服务器字段必须一次完成认证协调后再发布，禁止逐项 setter 暴露中间态。
pub fn main_stage_and_publish_server_config(
    id_server: String,
    relay_server: String,
    api_server: String,
    key: String,
) -> anyhow::Result<String> {
    let result =
        ui_interface::stage_and_publish_server_config(id_server, relay_server, api_server, key)?;
    serde_json::to_string(&result).map_err(|_| anyhow!("无法序列化服务器配置发布结果"))
}

pub fn main_test_if_valid_server(server: String, test_with_proxy: bool) -> String {
    test_if_valid_server(server, test_with_proxy)
}

pub fn main_set_socks(proxy: String, username: String, password: String) {
    set_socks(proxy, username, password)
}

pub fn main_get_proxy_status() -> bool {
    get_proxy_status()
}

pub fn main_get_socks() -> Vec<String> {
    get_socks()
}

pub fn main_get_app_name() -> String {
    get_app_name()
}

pub fn main_get_app_name_sync() -> SyncReturn<String> {
    SyncReturn(get_app_name())
}

pub fn main_uri_prefix_sync() -> SyncReturn<String> {
    SyncReturn(crate::get_uri_prefix())
}

pub fn main_get_license() -> String {
    get_license()
}

pub fn main_get_version() -> String {
    get_version()
}

pub fn main_get_fav() -> Vec<String> {
    get_fav()
}

pub fn main_store_fav(favs: Vec<String>) {
    store_fav(favs)
}

fn serialize_peer_config_for_flutter(config: &PeerConfig) -> String {
    // mainGetPeerSync 只有两个消费者：桌面标签读取 hostname，端口转发页读取
    // port_forwards。坚持字段白名单，避免完整 PeerConfig 的任何内部状态跨桥泄露。
    serde_json::to_string(&json!({
        "info": {
            "hostname": config.info.hostname.clone(),
        },
        "port_forwards": config.port_forwards.clone(),
    }))
    .unwrap_or_default()
}

pub fn main_get_peer_sync(id: String) -> SyncReturn<String> {
    SyncReturn(serialize_peer_config_for_flutter(&get_peer(id)))
}

pub fn main_get_lan_peers() -> String {
    serde_json::to_string(&get_lan_peers()).unwrap_or_default()
}

pub fn main_get_connect_status() -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        serde_json::to_string(&get_connect_status()).unwrap_or("".to_string())
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let mut state = hbb_common::config::get_online_state();
        if state > 0 {
            state = 1;
        }
        serde_json::json!({ "status_num": state }).to_string()
    }
}

pub fn main_check_connect_status() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    start_option_status_sync(); // avoid multi calls
}

pub fn main_is_using_public_server() -> bool {
    crate::using_public_server()
}

pub fn main_discover() {
    discover();
}

pub fn main_get_api_server() -> String {
    get_api_server()
}

pub fn main_deploy_device(token: String, id: String) -> String {
    #[cfg(target_os = "android")]
    {
        let new_id = match id.trim() {
            "" => None,
            id => Some(id.to_owned()),
        };
        ui_interface::deploy_device(token, new_id).message()
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (token, id);
        "Deployment is not supported on this platform.".to_owned()
    }
}

pub fn main_resolve_avatar_url(avatar: String) -> SyncReturn<String> {
    SyncReturn(resolve_avatar_url(avatar))
}

pub fn main_http_request(url: String, method: String, body: Option<String>, header: String) {
    http_request(url, method, body, header)
}

pub fn main_get_local_option(key: String) -> SyncReturn<String> {
    if protected_auth_bridge_key(&key) {
        return SyncReturn(String::new());
    }
    SyncReturn(get_local_option(key))
}

pub fn main_get_use_texture_render() -> SyncReturn<bool> {
    SyncReturn(use_texture_render())
}

pub fn main_get_env(key: String) -> SyncReturn<String> {
    if protected_auth_bridge_key(&key) {
        return SyncReturn(String::new());
    }
    SyncReturn(std::env::var(key).unwrap_or_default())
}

// Dart does not support changing environment variables.
// `Platform.environment['MY_VAR'] = 'VAR';` will throw an error
// `Unsupported operation: Cannot modify unmodifiable map`.
//
// And we need to share the environment variables between rust and dart isolates sometimes.
pub fn main_set_env(key: String, value: Option<String>) -> SyncReturn<()> {
    // 当前产品代码仅需要在远程终端子窗口标记管理员模式。禁止 Dart
    // 修改 APP_NAME、license 或其他会改变 effective API resolver 的环境输入。
    if key != "IS_TERMINAL_ADMIN" {
        return SyncReturn(());
    }
    let is_valid_key = !key.is_empty() && !key.contains('=') && !key.contains('\0');
    debug_assert!(is_valid_key, "Invalid environment variable key: {}", key);
    if !is_valid_key {
        log::error!("Invalid environment variable key: {}", key);
        return SyncReturn(());
    }

    match value {
        Some(v) => {
            let is_valid_value = !v.contains('\0');
            debug_assert!(is_valid_value, "Invalid environment variable value: {}", v);
            if !is_valid_value {
                log::error!("Invalid environment variable value: {}", v);
                return SyncReturn(());
            }
            std::env::set_var(key, v);
        }
        None => std::env::remove_var(key),
    }

    SyncReturn(())
}

pub fn main_set_local_option(key: String, value: String) {
    if protected_generic_write_key(&key) {
        return;
    }
    let is_texture_render_key = key.eq(config::keys::OPTION_TEXTURE_RENDER);
    let is_d3d_render_key = key.eq(config::keys::OPTION_ALLOW_D3D_RENDER);
    set_local_option(key, value.clone());
    if is_texture_render_key {
        let session_event = [("v", &value)];
        for session in sessions::get_sessions() {
            session.push_event("use_texture_render", &session_event, &[]);
            session.use_texture_render_changed();
            session.ui_handler.update_use_texture_render();
        }
    }
    if is_d3d_render_key {
        for session in sessions::get_sessions() {
            session.update_supported_decodings();
        }
    }
}

// We do use use `main_get_local_option` and `main_set_local_option`.
//
// 1. For get, the value is stored in the server process.
// 2. For clear, we need to need to return the error mmsg from the server process to flutter.
pub fn main_handle_wayland_screencast_restore_token(_key: String, _value: String) -> String {
    if protected_generic_write_key(&_key) {
        return String::new();
    }
    #[cfg(not(target_os = "linux"))]
    {
        return "".to_owned();
    }
    #[cfg(target_os = "linux")]
    if _value == "get" {
        match crate::ipc::get_wayland_screencast_restore_token(_key) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to get wayland screencast restore token, {}", e);
                "".to_owned()
            }
        }
    } else if _value == "clear" {
        match crate::ipc::clear_wayland_screencast_restore_token(_key.clone()) {
            Ok(true) => {
                set_local_option(_key, "".to_owned());
                "".to_owned()
            }
            Ok(false) => "Failed to clear, please try again.".to_owned(),
            Err(e) => format!("Failed to clear, {}", e),
        }
    } else {
        "".to_owned()
    }
}

pub fn main_get_input_source() -> SyncReturn<String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let input_source = get_cur_session_input_source();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let input_source = "".to_owned();
    SyncReturn(input_source)
}

pub fn main_set_input_source(session_id: SessionID, value: String) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        change_input_source(session_id, value);
        if let Some(session) = sessions::get_session_by_session_id(&session_id) {
            try_sync_peer_option(&session, &session_id, "input_source", None);
        }
    }
}

/// Set cursor position (for pointer lock re-centering).
///
/// # Returns
/// - `true`: cursor position was successfully set
/// - `false`: operation failed or not supported
///
/// # Platform behavior
/// - Windows/macOS/Linux: attempts to move the cursor to (x, y)
/// - Android/iOS: no-op, always returns `false`
pub fn main_set_cursor_position(x: i32, y: i32) -> SyncReturn<bool> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        SyncReturn(crate::set_cursor_pos(x, y))
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (x, y);
        SyncReturn(false)
    }
}

/// Clip cursor to a rectangle (for pointer lock).
///
/// When `enable` is true, the cursor is clipped to the rectangle defined by
/// `left`, `top`, `right`, `bottom`. When `enable` is false, the rectangle
/// values are ignored and the cursor is unclipped.
///
/// # Returns
/// - `true`: operation succeeded or no-op completed
/// - `false`: operation failed
///
/// # Platform behavior
/// - Windows: uses ClipCursor API to confine cursor to the specified rectangle
/// - macOS: uses CGAssociateMouseAndMouseCursorPosition for pointer lock effect;
///   the rect coordinates are ignored (only Some/None matters)
/// - Linux: no-op, always returns `true`; use pointer warping for similar effect
/// - Android/iOS: no-op, always returns `false`
pub fn main_clip_cursor(
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    enable: bool,
) -> SyncReturn<bool> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let rect = if enable {
            Some((left, top, right, bottom))
        } else {
            None
        };
        SyncReturn(crate::clip_cursor(rect))
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (left, top, right, bottom, enable);
        SyncReturn(false)
    }
}

pub fn main_get_my_id() -> String {
    get_id()
}

pub fn main_get_uuid() -> String {
    get_uuid()
}

pub fn main_get_peer_option(id: String, key: String) -> String {
    get_peer_option(id, key)
}

pub fn main_get_peer_option_sync(id: String, key: String) -> SyncReturn<String> {
    SyncReturn(get_peer_option(id, key))
}

// Sometimes we need to get the flutter option of a peer by reading the file.
// Because the session may not be established yet.
pub fn main_get_peer_flutter_option_sync(id: String, k: String) -> SyncReturn<String> {
    SyncReturn(get_peer_flutter_option(id, k))
}

pub fn main_set_peer_flutter_option_sync(id: String, k: String, v: String) -> SyncReturn<()> {
    set_peer_flutter_option(id, k, v);
    SyncReturn(())
}

pub fn main_set_peer_option(id: String, key: String, value: String) {
    set_peer_option(id, key, value)
}

pub fn main_set_peer_option_sync(id: String, key: String, value: String) -> SyncReturn<bool> {
    set_peer_option(id, key, value);
    SyncReturn(true)
}

pub fn main_set_peer_alias(id: String, alias: String) {
    set_peer_option(id, "alias".to_owned(), alias)
}

pub fn main_get_new_stored_peers() -> String {
    let peers: Vec<String> = config::NEW_STORED_PEER_CONFIG
        .lock()
        .unwrap()
        .drain()
        .collect();
    serde_json::to_string(&peers).unwrap_or_default()
}

pub fn main_forget_password(id: String) {
    forget_password(id)
}

pub fn main_peer_has_password(id: String) -> bool {
    peer_has_password(id)
}

pub fn main_peer_exists(id: String) -> bool {
    peer_exists(&id)
}

fn load_recent_peers(
    vec_id_modified_time_path: &Vec<(String, SystemTime, std::path::PathBuf)>,
    to_end: bool,
    all_peers: &mut Vec<HashMap<&str, String>>,
    from: usize,
) -> usize {
    let to = if to_end {
        Some(vec_id_modified_time_path.len())
    } else {
        None
    };
    let mut peers_next = PeerConfig::batch_peers(vec_id_modified_time_path, from, to);
    // There may be less peers than the batch size.
    // But no need to consider this case, because it is a rare case.
    let peers = peers_next.0.drain(..).map(|(id, _, p)| peer_to_map(id, p));
    all_peers.extend(peers);
    peers_next.1
}

pub fn main_load_recent_peers() {
    let push_to_flutter = |peers, ids| {
        let mut data = HashMap::from([("name", "load_recent_peers".to_owned()), ("peers", peers)]);
        if let Some(ids) = ids {
            data.insert("ids", ids);
        }
        let _res = flutter::push_global_event(
            flutter::APP_TYPE_MAIN,
            serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
        );
    };

    if !config::APP_DIR.read().unwrap().is_empty() {
        let vec_id_modified_time_path = PeerConfig::get_vec_id_modified_time_path(&None);
        if vec_id_modified_time_path.is_empty() {
            push_to_flutter("".to_owned(), None);
            return;
        }

        let load_two_times = vec_id_modified_time_path.len() > PeerConfig::BATCH_LOADING_COUNT
            && cfg!(target_os = "windows");
        let mut all_peers = vec![];
        if load_two_times {
            let next_from = load_recent_peers(&vec_id_modified_time_path, false, &mut all_peers, 0);
            let rest_ids = if next_from < vec_id_modified_time_path.len() {
                Some(
                    vec_id_modified_time_path[next_from..]
                        .iter()
                        .map(|(id, _, _)| id.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            } else {
                None
            };
            push_to_flutter(
                serde_json::ser::to_string(&all_peers).unwrap_or("".to_owned()),
                rest_ids,
            );
            let _ = load_recent_peers(&vec_id_modified_time_path, true, &mut all_peers, next_from);
        } else {
            let _ = load_recent_peers(&vec_id_modified_time_path, true, &mut all_peers, 0);
        }
        // Don't check if `all_peers` is empty, because we need this message to update the state in the flutter side.
        push_to_flutter(
            serde_json::ser::to_string(&all_peers).unwrap_or("".to_owned()),
            None,
        );
    } else {
        push_to_flutter("".to_owned(), None)
    }
}

pub fn main_load_recent_peers_for_ab(filter: String) -> String {
    let id_filters = serde_json::from_str::<Vec<String>>(&filter).unwrap_or_default();
    let id_filters = if id_filters.is_empty() {
        None
    } else {
        Some(id_filters)
    };
    if !config::APP_DIR.read().unwrap().is_empty() {
        let peers: Vec<HashMap<&str, String>> = PeerConfig::peers(id_filters)
            .drain(..)
            .map(|(id, _, p)| peer_to_map(id, p))
            .collect();
        return serde_json::ser::to_string(&peers).unwrap_or("".to_owned());
    }
    "".to_string()
}

pub fn main_load_fav_peers() {
    let push_to_flutter = |peers| {
        let data = HashMap::from([("name", "load_fav_peers".to_owned()), ("peers", peers)]);
        let _res = flutter::push_global_event(
            flutter::APP_TYPE_MAIN,
            serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
        );
    };
    if !config::APP_DIR.read().unwrap().is_empty() {
        let favs = get_fav();
        let mut recent = PeerConfig::peers(Some(favs.clone()));
        let mut lan = config::LanPeers::load()
            .peers
            .iter()
            .filter(|d| favs.contains(&d.id) && recent.iter().all(|r| r.0 != d.id))
            .map(|d| {
                (
                    d.id.clone(),
                    SystemTime::UNIX_EPOCH,
                    PeerConfig {
                        info: PeerInfoSerde {
                            username: d.username.clone(),
                            hostname: d.hostname.clone(),
                            platform: d.platform.clone(),
                        },
                        ..Default::default()
                    },
                )
            })
            .collect();
        recent.append(&mut lan);
        let peers: Vec<HashMap<&str, String>> = recent
            .into_iter()
            .map(|(id, _, p)| peer_to_map(id, p))
            .collect();

        push_to_flutter(serde_json::ser::to_string(&peers).unwrap_or("".to_owned()));
    } else {
        push_to_flutter("".to_owned());
    }
}

pub fn main_load_lan_peers() {
    let data = HashMap::from([
        ("name", "load_lan_peers".to_owned()),
        (
            "peers",
            serde_json::to_string(&get_lan_peers()).unwrap_or_default(),
        ),
    ]);
    let _res = flutter::push_global_event(
        flutter::APP_TYPE_MAIN,
        serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
    );
}

pub fn main_remove_discovered(id: String) {
    remove_discovered(id);
}

fn main_broadcast_message(data: &HashMap<&str, &str>) {
    let event = serde_json::ser::to_string(&data).unwrap_or("".to_owned());
    for app in flutter::get_global_event_channels() {
        if app == flutter::APP_TYPE_MAIN || app == flutter::APP_TYPE_CM {
            continue;
        }
        let _res = flutter::push_global_event(&app, event.clone());
    }
}

pub fn main_change_theme(dark: String) {
    main_broadcast_message(&HashMap::from([("name", "theme"), ("dark", &dark)]));
    #[cfg(not(any(target_os = "ios")))]
    send_to_cm(&crate::ipc::Data::Theme(dark));
}

pub fn main_change_language(lang: String) {
    main_broadcast_message(&HashMap::from([("name", "language"), ("lang", &lang)]));
    #[cfg(not(any(target_os = "ios")))]
    send_to_cm(&crate::ipc::Data::Language(lang));
}

pub fn main_video_save_directory(root: bool) -> SyncReturn<String> {
    SyncReturn(video_save_directory(root))
}

pub fn main_set_user_default_option(key: String, value: String) {
    set_user_default_option(key, value);
}

pub fn main_get_user_default_option(key: String) -> SyncReturn<String> {
    SyncReturn(get_user_default_option(key))
}

pub fn main_handle_relay_id(id: String) -> String {
    handle_relay_id(&id).to_owned()
}

pub fn main_is_option_fixed(key: String) -> SyncReturn<bool> {
    SyncReturn(is_option_fixed(&key))
}

pub fn main_get_main_display() -> SyncReturn<String> {
    #[cfg(target_os = "ios")]
    let display_info = "".to_owned();
    #[cfg(not(target_os = "ios"))]
    let mut display_info = "".to_owned();
    #[cfg(not(target_os = "ios"))]
    {
        #[cfg(not(target_os = "linux"))]
        let is_linux_wayland = false;
        #[cfg(target_os = "linux")]
        let is_linux_wayland = !is_x11();

        if !is_linux_wayland {
            if let Ok(displays) = crate::display_service::try_get_displays() {
                // to-do: Need to detect current display index.
                if let Some(display) = displays.iter().next() {
                    display_info = serde_json::to_string(&HashMap::from([
                        ("w", display.width()),
                        ("h", display.height()),
                    ]))
                    .unwrap_or_default();
                }
            }
        }

        #[cfg(target_os = "linux")]
        if is_linux_wayland {
            let displays = scrap::wayland::display::get_displays();
            if let Some(display) = displays.displays.get(displays.primary) {
                let logical_size = display
                    .logical_size
                    .unwrap_or((display.width, display.height));
                display_info = serde_json::to_string(&HashMap::from([
                    ("w", logical_size.0),
                    ("h", logical_size.1),
                ]))
                .unwrap_or_default();
            }
        }
    }
    SyncReturn(display_info)
}

// No need to check if is on Wayland in this function.
// The Flutter side gets display information on Wayland using a different method.
pub fn main_get_displays() -> SyncReturn<String> {
    #[cfg(target_os = "ios")]
    let display_info = "".to_owned();
    #[cfg(not(target_os = "ios"))]
    let mut display_info = "".to_owned();
    #[cfg(not(target_os = "ios"))]
    if let Ok(displays) = crate::display_service::try_get_displays() {
        let displays = displays
            .iter()
            .map(|d| {
                HashMap::from([
                    ("x", d.origin().0),
                    ("y", d.origin().1),
                    ("w", d.width() as i32),
                    ("h", d.height() as i32),
                ])
            })
            .collect::<Vec<_>>();
        display_info = serde_json::to_string(&displays).unwrap_or_default();
    }
    SyncReturn(display_info)
}

pub fn session_add_port_forward(
    session_id: SessionID,
    local_port: i32,
    remote_host: String,
    remote_port: i32,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.add_port_forward(local_port, remote_host, remote_port);
    }
}

pub fn session_remove_port_forward(session_id: SessionID, local_port: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.remove_port_forward(local_port);
    }
}

pub fn session_new_rdp(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.new_rdp();
    }
}

pub fn session_request_voice_call(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.request_voice_call();
    }
}

pub fn session_close_voice_call(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.close_voice_call();
    }
}

pub fn session_get_conn_token(session_id: SessionID) -> SyncReturn<Option<String>> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.get_conn_token())
    } else {
        SyncReturn(None)
    }
}

pub fn cm_handle_incoming_voice_call(id: i32, accept: bool) {
    crate::ui_cm_interface::handle_incoming_voice_call(id, accept);
}

pub fn cm_close_voice_call(id: i32) {
    crate::ui_cm_interface::close_voice_call(id);
}

pub fn set_voice_call_input_device(_is_cm: bool, _device: String) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if _is_cm {
        let _ = crate::ipc::set_config("voice-call-input", _device);
    } else {
        crate::audio_service::set_voice_call_input_device(Some(_device), true);
    }
}

pub fn get_voice_call_input_device(_is_cm: bool) -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if _is_cm {
        match crate::ipc::get_config("voice-call-input") {
            Ok(Some(device)) => device,
            _ => "".to_owned(),
        }
    } else {
        crate::audio_service::get_voice_call_input_device().unwrap_or_default()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    "".to_owned()
}

pub fn main_get_last_remote_id() -> String {
    LocalConfig::get_remote_id()
}

pub fn main_get_software_update_url() {
    crate::common::check_software_update();
}

pub fn main_get_home_dir() -> String {
    fs::get_home_as_string()
}

pub fn main_get_langs() -> String {
    get_langs()
}

pub fn main_get_temporary_password() -> String {
    ui_interface::temporary_password()
}

pub fn main_set_permanent_password_with_result(password: String) -> bool {
    ui_interface::set_permanent_password_with_result(password)
}

pub fn main_get_fingerprint() -> String {
    get_fingerprint()
}

pub fn cm_get_clients_state() -> String {
    crate::ui_cm_interface::get_clients_state()
}

pub fn cm_check_clients_length(length: usize) -> Option<String> {
    if length != crate::ui_cm_interface::get_clients_length() {
        Some(crate::ui_cm_interface::get_clients_state())
    } else {
        None
    }
}

pub fn cm_get_clients_length() -> usize {
    crate::ui_cm_interface::get_clients_length()
}

pub fn main_init(app_dir: String, custom_client_config: String) {
    let _ = FLUTTER_AUTH_APP_DIR.set(PathBuf::from(&app_dir));
    initialize(&app_dir, &custom_client_config);
}

/// 仅由 Flutter 主界面在 `main_init` 完成后显式调用。
pub fn main_auth_initialize(app_type: String, package_identity: String) -> anyhow::Result<String> {
    auth_binding::require_trusted_main_ui_process()?;
    if app_type != flutter::APP_TYPE_MAIN {
        hbb_common::bail!("非主界面进程不得初始化权威认证状态");
    }
    ui_interface::wait_for_authoritative_options_before_auth(Duration::from_secs(5))?;
    auth_binding::scrub_legacy_auth_mirror();
    let anchor = flutter_auth_authority_anchor(&package_identity)?;
    auth_binding::initialize_main_ui_auth(anchor)?;
    let effective_api_base = ui_interface::get_api_server();
    auth_binding::reconcile_effective_api_base_before_publish(
        &effective_api_base,
        &effective_api_base,
        current_flutter_device_identity(),
    )?;
    ui_interface::ensure_audit_capability_ipc_server_started();
    crate::hbbs_http::address_book_sync::ensure_worker_started();
    crate::hbbs_http::address_book_sync::wake_worker();
    serialize_auth_snapshot(&auth_binding::auth_snapshot()?)
}

/// 仅供用户确认损坏状态后显式重建；普通登录流程不得自动调用。
pub fn main_auth_reset_local_state(
    app_type: String,
    package_identity: String,
    confirmed: bool,
) -> anyhow::Result<String> {
    auth_binding::require_trusted_main_ui_process()?;
    if app_type != flutter::APP_TYPE_MAIN || !confirmed {
        hbb_common::bail!("重建本地认证状态需要主界面用户明确确认");
    }
    let anchor = flutter_auth_authority_anchor(&package_identity)?;
    auth_binding::reset_local_auth_state(anchor)?;
    ui_interface::ensure_audit_capability_ipc_server_started();
    crate::hbbs_http::address_book_sync::ensure_worker_started();
    crate::hbbs_http::address_book_sync::wake_worker();
    serialize_auth_snapshot(&auth_binding::auth_snapshot()?)
}

/// 返回不含 token 的权威认证状态快照。
pub fn main_auth_snapshot() -> anyhow::Result<String> {
    serialize_auth_snapshot(&auth_binding::auth_snapshot()?)
}

pub fn main_get_address_book_consumer_registration() -> anyhow::Result<String> {
    let (sink_generation, sink_present) = flutter::address_book_consumer_registration();
    serde_json::to_string(&json!({
        "sink_generation": sink_generation,
        "sink_present": sink_present,
    }))
    .map_err(|_| anyhow!("无法序列化地址簿 consumer 状态"))
}

pub fn main_address_book_consumer_ready(sink_generation: u64) -> bool {
    let ready = flutter::mark_address_book_consumer_ready(sink_generation);
    if ready && auth_binding::is_main_ui_auth_initialized() {
        crate::hbbs_http::address_book_sync::ensure_worker_started();
        crate::hbbs_http::address_book_sync::wake_worker();
    }
    ready
}

/// 捕获一次无秘密、可跨分页复用的认证请求句柄。
pub fn main_auth_begin_request(url: String) -> anyhow::Result<String> {
    let handle = auth_binding::credentialed_request_handle(&url)?;
    let session = session_for_handle(&handle)?;
    serde_json::to_string(&request_envelope(handle, session))
        .map_err(|_| anyhow!("无法序列化认证请求句柄"))
}

pub fn main_auth_is_request_current(handle_json: String) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    Ok(auth_binding::is_request_current(&request.handle))
}

/// 严格凭证请求只在 Rust 内部取得并注入 Bearer。
pub fn main_auth_strict_request(
    handle_json: String,
    url: String,
    method: String,
    body: Option<String>,
    headers_json: String,
    timeout_ms: u64,
) -> anyhow::Result<String> {
    if body
        .as_ref()
        .is_some_and(|value| value.len() > ISSUE9_MAX_FFI_JSON_BYTES)
    {
        hbb_common::bail!("严格HTTP请求体过大");
    }
    if timeout_ms == 0 || timeout_ms > 60_000 {
        hbb_common::bail!("严格HTTP超时参数无效");
    }
    let request_context = parse_credentialed_request(&handle_json)?;
    let session = session_for_handle(&request_context.handle)?;
    let method = parse_strict_method(&method)?;
    let operation = classify_session_operation(method, &url, &session.normalized_api_base)?;
    let native_context = auth_binding::credentialed_context(&request_context.handle, &url)?;
    let mut request =
        StrictHttpRequest::new(method, url.clone()).timeout(Duration::from_millis(timeout_ms));
    request.body = body.map(String::into_bytes);
    request.headers = parse_strict_headers(&headers_json)?;
    let commercial_mutation_guid = if operation == FfiSessionOperation::AddressBookCommercial {
        commercial_address_book_mutation_guid(method, &url, &session.normalized_api_base)?
    } else {
        None
    };
    let personal_mutation_started = if operation == FfiSessionOperation::AddressBookWrite {
        if !auth_binding::begin_personal_hash_mutation_if_current(&request_context.handle, None)? {
            hbb_common::bail!("legacy personal mutation 请求句柄已失效");
        }
        true
    } else if let Some(guid) = commercial_mutation_guid.as_deref() {
        let matched_personal = auth_binding::begin_personal_hash_mutation_if_current(
            &request_context.handle,
            Some(guid),
        )?;
        if !matched_personal {
            // 同一组端点也承载 shared profile。无法证明为当前 personal GUID 时按潜在
            // personal 写入保守失效，但不能破坏共享地址簿编辑能力。
            if !auth_binding::begin_personal_hash_mutation_if_current(
                &request_context.handle,
                None,
            )? {
                hbb_common::bail!("商业地址簿 mutation 请求句柄已失效");
            }
        }
        true
    } else {
        false
    };
    // 该值只存在于 native 调用栈，Dart 既不能提供也不能重放。
    let personal_hash_request_fence =
        auth_binding::personal_hash_request_fence(&request_context.handle)?;
    let response_result = strict_http_request_blocking(&request_context.handle, request);
    if personal_mutation_started {
        // 即使传输失败也必须结束并再次推进栅栏；服务端可能已经完成提交。
        let _ = auth_binding::finish_personal_hash_mutation_if_current(&request_context.handle)?;
    }
    let mut response = response_result?;
    if response.body.contains(&native_context.access_token) {
        hbb_common::bail!("严格HTTP响应包含禁止返回的会话凭证");
    }
    let _ = session_for_handle(&request_context.handle)?;
    if operation == FfiSessionOperation::CurrentUser && (200..300).contains(&response.status) {
        response.body = sanitize_current_user_response(&response.body)?;
    }
    let personal_hash_receipt = observe_native_personal_hash_response(
        &request_context.handle,
        personal_hash_request_fence,
        operation,
        &url,
        response.status,
        response.content_type.as_deref(),
        &response.body,
    )?;
    let output = FfiStrictHttpResponse {
        request_id: request_context.handle.request_context_id,
        status: response.status,
        content_type: response.content_type,
        retry_after: response.retry_after,
        body: response.body,
        normalized_api_base: request_context.handle.normalized_api_base,
        namespace: request_context.handle.namespace,
        session_epoch: request_context.handle.session_epoch,
        session_nonce: request_context.handle.session_nonce,
        cursor_key: request_context.handle.cursor_key,
        cursor: request_context.cursor,
        personal_hash_receipt,
    };
    serde_json::to_string(&output).map_err(|_| anyhow!("无法序列化严格HTTP响应"))
}

fn parse_auth_attempt(attempt_json: &str) -> ResultType<AuthAttempt> {
    if attempt_json.is_empty() || attempt_json.len() > ISSUE9_MAX_AUTH_ATTEMPT_BYTES {
        hbb_common::bail!("登录请求能力大小无效");
    }
    let attempt: AuthAttempt =
        serde_json::from_str(attempt_json).map_err(|_| anyhow!("登录请求能力格式无效"))?;
    if attempt.attempt_id == 0
        || attempt.attempt_id > ISSUE9_MAX_SAFE_INTEGER
        || attempt.logout_generation > ISSUE9_MAX_SAFE_INTEGER
        || attempt.nonce.is_empty()
        || attempt.nonce.len() > ISSUE9_MAX_SAFE_TEXT_BYTES
        || attempt.nonce.chars().any(char::is_control)
        || attempt.normalized_api_base.is_empty()
        || attempt.normalized_api_base.len() > ISSUE9_MAX_SAFE_TEXT_BYTES
        || attempt.normalized_api_base.chars().any(char::is_control)
    {
        hbb_common::bail!("登录请求能力字段无效");
    }
    Ok(attempt)
}

/// 在 native 权威中开始一次登录；后续挑战必须复用返回的同一能力。
pub fn main_auth_begin_login() -> anyhow::Result<String> {
    let attempt = ui_interface::begin_account_auth_attempt()?;
    auth_binding::serialize_auth_attempt(&attempt)
}

/// 在产生 UI 副作用前复验登录或 OIDC 请求仍属于当前代次。
pub fn main_auth_attempt_is_current(attempt_json: String) -> anyhow::Result<bool> {
    let attempt = parse_auth_attempt(&attempt_json)?;
    Ok(auth_binding::is_auth_attempt_current(&attempt))
}

/// 只取消调用方持有的登录代次，绝不清除后来开始的请求。
pub fn main_auth_cancel_attempt(attempt_json: String) -> anyhow::Result<bool> {
    let attempt = parse_auth_attempt(&attempt_json)?;
    crate::hbbs_http::account::OidcSession::auth_cancel_attempt(&attempt)
}

/// UI 接纳成功 DTO 后 ACK exact attempt；此前不会启动 credentialed worker。
pub fn main_auth_ack_attempt(attempt_json: String) -> anyhow::Result<bool> {
    let attempt = parse_auth_attempt(&attempt_json)?;
    crate::hbbs_http::account::OidcSession::ack_auth_attempt(&attempt)
}

/// 登录成功时 token 只进入 native 权威状态，绝不返回 Dart。
pub fn main_auth_strict_login_and_commit(
    attempt_json: String,
    login_body: String,
) -> anyhow::Result<String> {
    let validated_login_body = validate_and_normalize_login_body(&login_body)?;
    let attempt = parse_auth_attempt(&attempt_json)?;
    if !auth_binding::is_auth_attempt_current(&attempt) {
        hbb_common::bail!("登录请求已失效");
    }

    let login_url = endpoint_from_base(&attempt.normalized_api_base, "api/login")?;
    let (_in_flight_claim, response) = auth_binding::claim_auth_attempt_and_send(
        &attempt,
        auth_binding::is_auth_attempt_current,
        || {
            strict_http_request_no_bearer_blocking(
                RequestSecurityClass::LoginStrict,
                StrictHttpRequest::new(StrictHttpMethod::Post, login_url)
                    .json_body(validated_login_body),
            )
        },
    )?;
    let Some(response) = response else {
        hbb_common::bail!("登录请求已失效");
    };
    let response = match response {
        Ok(response) => response,
        Err(_) if auth_binding::is_auth_attempt_current(&attempt) => {
            return serialize_login_outcome_if_current(
                &attempt,
                json!({
                    "kind": "transport_error",
                    "status": 0,
                    "message": "登录请求失败",
                    "native_attempt": attempt_json,
                }),
            );
        }
        Err(_) => hbb_common::bail!("登录请求已失效"),
    };
    if !auth_binding::is_auth_attempt_current(&attempt) {
        hbb_common::bail!("登录请求已失效");
    }

    if response.body.len() > ISSUE9_MAX_LOGIN_BODY_BYTES {
        return serialize_login_outcome_if_current(
            &attempt,
            json!({
                "kind": "protocol_error",
                "status": response.status,
                "message": "登录响应体过大",
                "native_attempt": attempt_json,
            }),
        );
    }
    if !(200..300).contains(&response.status) {
        return serialize_login_outcome_if_current(
            &attempt,
            json!({
                "kind": "http_error",
                "status": response.status,
                "retry_after": response.retry_after,
                "message": "登录失败",
                "native_attempt": attempt_json,
            }),
        );
    }
    let mime = response
        .content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !mime.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return serialize_login_outcome_if_current(
            &attempt,
            json!({
                "kind": "protocol_error",
                "status": response.status,
                "message": "登录响应Content-Type无效",
                "native_attempt": attempt_json,
            }),
        );
    }

    let Value::Object(mut body) =
        serde_json::from_str::<Value>(&response.body).unwrap_or(Value::Null)
    else {
        return serialize_login_outcome_if_current(
            &attempt,
            json!({
                "kind": "protocol_error",
                "status": response.status,
                "message": "登录响应格式无效",
                "native_attempt": attempt_json,
            }),
        );
    };
    let response_type = safe_user_text(&body, "type")?;
    if response_type == "access_token" {
        let access_token = body
            .remove("access_token")
            .and_then(|value| value.as_str().map(str::to_owned))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("登录响应缺少访问凭证"))?;
        let safe_user = body
            .get("user")
            .ok_or_else(|| anyhow!("登录响应缺少用户信息"))
            .and_then(parse_safe_auth_user)?;
        let expires_at = login_expiry_hint(&body);
        let snapshot = crate::hbbs_http::account::OidcSession::commit_external_auth_attempt(
            &attempt,
            access_token,
            safe_user,
            expires_at,
        )?;
        let session = snapshot
            .session
            .ok_or_else(|| anyhow!("登录提交后没有有效认证会话"))?;
        return Ok(json!({
            "kind": "authenticated",
            "status": response.status,
            "user": auth_safe_user_ui_value(&session.safe_user),
            "normalized_api_base": session.normalized_api_base,
            "namespace": session.namespace,
            "cursor_key": session.cursor_key,
            "session_epoch": session.session_epoch,
            "session_nonce": session.session_nonce,
            "cursor": session.cursor,
            "capability": session.capability,
            "force_full_pending": session.force_full_pending,
            "native_attempt": attempt_json,
        })
        .to_string());
    }

    if !auth_binding::is_auth_attempt_current(&attempt) {
        hbb_common::bail!("登录请求已失效");
    }
    serialize_login_challenge(&body, response.status, &attempt_json)
}

/// 本地注销只等待 durable tombstone；远端撤销由独立重试循环锁外完成。
pub fn main_auth_logout(device_id: String, device_uuid: String) -> anyhow::Result<String> {
    let identity_valid = !device_id.is_empty()
        && !device_uuid.is_empty()
        && device_id.chars().count() <= 100
        && !device_id.chars().any(char::is_control)
        && device_uuid.len() <= 512
        && !device_uuid.chars().any(char::is_control);
    let identity = if identity_valid {
        DeviceIdentitySnapshot {
            id: device_id,
            uuid: device_uuid,
        }
    } else {
        DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        }
    };
    let ticket = auth_binding::begin_logout_current(identity)?;
    crate::hbbs_http::address_book_sync::wake_worker();
    let outcome = if ticket.is_some() {
        json!({"outcome": "queued"})
    } else {
        json!({"outcome": "no_active_session"})
    };
    let snapshot = auth_binding::auth_snapshot()?;
    Ok(json!({
        "result": outcome,
        "snapshot": snapshot
    })
    .to_string())
}

/// 应用重启后重试持久化的远端注销；结果只含状态，不含 ticket 中的 token 或认证请求体。
pub fn main_auth_retry_pending_logouts() -> anyhow::Result<String> {
    let tickets = auth_binding::pending_logout_tickets()?;
    let mut outcomes = Vec::with_capacity(tickets.len());
    for ticket in tickets {
        let outcome = match auth_binding::retry_pending_logout_blocking(&ticket) {
            Ok(outcome) => {
                serde_json::to_value(outcome).unwrap_or_else(|_| json!({"outcome": "retained"}))
            }
            Err(_) => json!({"outcome": "retained"}),
        };
        outcomes.push(outcome);
    }
    Ok(json!({
        "attempted": outcomes.len(),
        "outcomes": outcomes,
        "snapshot": auth_binding::auth_snapshot()?
    })
    .to_string())
}

pub fn main_auth_clear_if_current(handle_json: String) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    let cleared = auth_binding::clear_auth_session_if_current(&request.handle)?;
    if cleared {
        crate::hbbs_http::address_book_sync::wake_worker();
    }
    Ok(cleared)
}

pub fn main_auth_compare_and_set_cursor(
    handle_json: String,
    expected: i64,
    target: i64,
    allow_reset: bool,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    if expected < 0
        || target < 0
        || expected as u64 > ISSUE9_MAX_SAFE_INTEGER
        || target as u64 > ISSUE9_MAX_SAFE_INTEGER
        || expected as u64 != request.cursor
    {
        hbb_common::bail!("地址簿cursor参数无效");
    }
    auth_binding::compare_and_set_cursor(
        &request.handle,
        expected as u64,
        target as u64,
        allow_reset,
    )
}

pub fn main_auth_set_address_book_capability(
    handle_json: String,
    capability: String,
    force_full_pending: bool,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    let capability = match capability.trim().to_ascii_lowercase().as_str() {
        "unknown" => AddressBookCapability::Unknown,
        "issue9_v2" => AddressBookCapability::Issue9V2,
        "legacy" => AddressBookCapability::Legacy,
        "commercial_multi" => AddressBookCapability::CommercialMulti,
        _ => hbb_common::bail!("未知的地址簿能力"),
    };
    let changed =
        auth_binding::set_address_book_capability(&request.handle, capability, force_full_pending)?;
    if changed {
        crate::hbbs_http::address_book_sync::wake_worker();
    }
    Ok(changed)
}

/// 模型提交后一次性消费 native strict 响应签发的 receipt，Dart 不提供 hash 材料。
pub fn main_auth_commit_personal_hash_receipt(
    handle_json: String,
    receipt_id: String,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    if receipt_id.is_empty() || receipt_id.len() > 64 {
        hbb_common::bail!("个人地址簿 hash receipt 无效");
    }
    auth_binding::commit_personal_hash_receipt(&request.handle, &receipt_id)
}

/// personal 内容发生非完整变更或确认 v2 时，立即撤销当前代的全部兼容 hash。
pub fn main_auth_clear_personal_hash_allowlist_if_current(
    handle_json: String,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    auth_binding::clear_personal_hash_allowlist_if_current(&request.handle)
}

/// 模型与 UI 都提交成功后，才允许 ACK cursor 并完成本代 v2 能力。
pub fn main_auth_complete_address_book_pull(
    handle_json: String,
    expected: i64,
    target: i64,
    allow_reset: bool,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    if expected < 0
        || target < 0
        || expected as u64 > ISSUE9_MAX_SAFE_INTEGER
        || target as u64 > ISSUE9_MAX_SAFE_INTEGER
        || expected as u64 != request.cursor
    {
        hbb_common::bail!("地址簿完成参数无效");
    }
    if !auth_binding::complete_address_book_pull(
        &request.handle,
        expected as u64,
        target as u64,
        allow_reset,
    )? {
        return Ok(false);
    }
    crate::hbbs_http::address_book_sync::wake_worker();
    Ok(true)
}

pub fn main_auth_mark_pro(handle_json: String) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    auth_binding::mark_pro_if_current(&request.handle)
}

pub fn main_auth_wake_address_book_sync() {
    if auth_binding::is_main_ui_auth_initialized() {
        crate::hbbs_http::address_book_sync::ensure_worker_started();
        crate::hbbs_http::address_book_sync::wake_worker();
    }
}

pub fn main_device_id(id: String) {
    *crate::common::DEVICE_ID.lock().unwrap() = id;
}

pub fn main_device_name(name: String) {
    *crate::common::DEVICE_NAME.lock().unwrap() = name;
}

pub fn main_remove_peer(id: String) {
    PeerConfig::remove(&id);
}

pub fn main_has_hwcodec() -> SyncReturn<bool> {
    SyncReturn(has_hwcodec())
}

pub fn main_has_vram() -> SyncReturn<bool> {
    SyncReturn(has_vram())
}

pub fn main_supported_hwdecodings() -> SyncReturn<String> {
    let decoding = supported_hwdecodings();
    let msg = HashMap::from([("h264", decoding.0), ("h265", decoding.1)]);

    SyncReturn(serde_json::ser::to_string(&msg).unwrap_or("".to_owned()))
}

pub fn main_is_root() -> bool {
    is_root()
}

pub fn get_double_click_time() -> SyncReturn<i32> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        return SyncReturn(crate::platform::get_double_click_time() as _);
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    SyncReturn(500i32)
}

pub fn main_start_dbus_server() {
    #[cfg(target_os = "linux")]
    {
        use crate::dbus::start_dbus_server;
        // spawn new thread to start dbus server
        std::thread::spawn(|| {
            let _ = start_dbus_server();
        });
    }
}

pub fn main_auth_save_ab_cache_if_current(
    handle_json: String,
    payload_json: String,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    validate_auth_cache_payload(&payload_json, &request.handle.cursor_key)?;
    Ok(
        auth_binding::with_current_credentialed_request(&request.handle, || {
            let _cache_guard = AUTH_CACHE_IO_LOCK
                .lock()
                .map_err(|_| anyhow!("认证缓存互斥锁已损坏"))?;
            store_auth_cache_json(AuthCacheKind::AddressBook, &payload_json)
        })?
        .is_some(),
    )
}

pub fn main_auth_save_group_cache_if_current(
    handle_json: String,
    payload_json: String,
) -> anyhow::Result<bool> {
    let request = parse_credentialed_request(&handle_json)?;
    validate_auth_cache_payload(&payload_json, &request.handle.cursor_key)?;
    Ok(
        auth_binding::with_current_credentialed_request(&request.handle, || {
            let _cache_guard = AUTH_CACHE_IO_LOCK
                .lock()
                .map_err(|_| anyhow!("认证缓存互斥锁已损坏"))?;
            store_auth_cache_json(AuthCacheKind::Group, &payload_json)
        })?
        .is_some(),
    )
}

pub fn main_clear_ab_if_namespace(auth_namespace: String) -> anyhow::Result<bool> {
    let _cache_guard = AUTH_CACHE_IO_LOCK
        .lock()
        .map_err(|_| anyhow!("认证缓存互斥锁已损坏"))?;
    clear_auth_cache_if_namespace(AuthCacheKind::AddressBook, &auth_namespace)
}

pub fn main_clear_group_if_namespace(auth_namespace: String) -> anyhow::Result<bool> {
    let _cache_guard = AUTH_CACHE_IO_LOCK
        .lock()
        .map_err(|_| anyhow!("认证缓存互斥锁已损坏"))?;
    clear_auth_cache_if_namespace(AuthCacheKind::Group, &auth_namespace)
}

pub fn main_save_ab(json: String) {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return;
    };
    if let Err(error) = store_auth_cache_json(AuthCacheKind::AddressBook, &json) {
        log::error!("地址簿缓存写入失败: {error}");
    }
}

pub fn main_clear_ab() {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return;
    };
    if let Err(error) = std::fs::remove_file(auth_cache_path(AuthCacheKind::AddressBook)) {
        if error.kind() != std::io::ErrorKind::NotFound {
            log::error!("地址簿缓存删除失败: {error}");
        }
    }
}

pub fn main_load_ab() -> String {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return "{}".to_owned();
    };
    load_auth_cache_json(AuthCacheKind::AddressBook).unwrap_or_else(|error| {
        log::error!("地址簿缓存读取失败: {error}");
        "{}".to_owned()
    })
}

pub fn main_save_group(json: String) {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return;
    };
    if let Err(error) = store_auth_cache_json(AuthCacheKind::Group, &json) {
        log::error!("群组缓存写入失败: {error}");
    }
}

pub fn main_clear_group() {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return;
    };
    if let Err(error) = std::fs::remove_file(auth_cache_path(AuthCacheKind::Group)) {
        if error.kind() != std::io::ErrorKind::NotFound {
            log::error!("群组缓存删除失败: {error}");
        }
    }
}

pub fn main_load_group() -> String {
    let Ok(_cache_guard) = AUTH_CACHE_IO_LOCK.lock() else {
        log::error!("认证缓存互斥锁已损坏");
        return "{}".to_owned();
    };
    load_auth_cache_json(AuthCacheKind::Group).unwrap_or_else(|error| {
        log::error!("群组缓存读取失败: {error}");
        "{}".to_owned()
    })
}

pub fn session_send_pointer(session_id: SessionID, msg: String) {
    super::flutter::session_send_pointer(session_id, msg);
}

/// Send mouse event from Flutter to the remote peer.
///
/// # Relative Mouse Mode Message Contract
///
/// When the message contains a `relative_mouse_mode` field, this function validates
/// and filters activation/deactivation markers.
///
/// **Mode Authority:**
/// The Flutter InputModel is authoritative for relative mouse mode activation/deactivation.
/// The server (via `input_service.rs`) only consumes forwarded delta movements and tracks
/// relative movement processing state, but does NOT control mode activation/deactivation.
///
/// **Deactivation Markers are Local-Only:**
/// Deactivation markers (`relative_mouse_mode: "0"`) are NEVER forwarded to the server.
/// They are handled entirely on the client side to reset local UI state (cursor visibility,
/// pointer lock, etc.). The server does not rely on deactivation markers and should not
/// expect to receive them.
///
/// **Contract (Flutter side MUST adhere to):**
/// 1. `relative_mouse_mode` field is ONLY present on activation/deactivation marker messages,
///    NEVER on normal pointer events (move, button, scroll).
/// 2. Deactivation marker: `{"relative_mouse_mode": "0"}` - local-only, never forwarded.
/// 3. Activation marker: `{"relative_mouse_mode": "1", "type": "move_relative", "x": "0", "y": "0"}`
///    - MUST use `type="move_relative"` with `x="0"` and `y="0"` (safe no-op).
///    - Any other combination is dropped to prevent accidental cursor movement.
///
/// If these assumptions are violated (e.g., `relative_mouse_mode` is added to normal events),
/// legitimate mouse events may be silently dropped by the early-return logic below.
pub fn session_send_mouse(session_id: SessionID, msg: String) {
    if let Ok(m) = serde_json::from_str::<HashMap<String, String>>(&msg) {
        // Relative mouse mode marker validation (Flutter-only).
        // This only validates and filters markers; the server tracks per-connection
        // relative-movement processing state but not mode activation/deactivation.
        // See doc comment above for the message contract.
        if let Some(v) = m.get("relative_mouse_mode") {
            let active = matches!(v.as_str(), "1" | "Y" | "on");

            // Disable marker: local-only, never forwarded to the server.
            // The server does not track mode deactivation; it simply stops receiving
            // relative move events when the client exits relative mouse mode.
            if !active {
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                crate::keyboard::set_relative_mouse_mode_state(false);
                return;
            }

            // Enable marker: validate BEFORE setting state to avoid desync.
            // This ensures we only mark as active if the marker will actually be forwarded.

            // Enable marker is allowed to go through only if it's a safe no-op relative move.
            // This avoids accidentally moving the remote cursor (e.g. if type/x/y are missing).
            let msg_type = m.get("type").map(|t| t.as_str());
            if msg_type != Some("move_relative") {
                log::warn!(
                    "relative_mouse_mode activation marker has invalid type: {:?}, expected 'move_relative'. Dropping.",
                    msg_type
                );
                return;
            }
            let x_marker = m
                .get("x")
                .map(|x| x.parse::<i32>().unwrap_or(0))
                .unwrap_or(0);
            let y_marker = m
                .get("y")
                .map(|y| y.parse::<i32>().unwrap_or(0))
                .unwrap_or(0);
            if x_marker != 0 || y_marker != 0 {
                log::warn!(
                    "relative_mouse_mode activation marker has non-zero coordinates: x={}, y={}. Dropping.",
                    x_marker, y_marker
                );
                return;
            }

            // Guard against unexpected fields that could turn this no-op into a real event.
            if m.contains_key("buttons")
                || m.contains_key("alt")
                || m.contains_key("ctrl")
                || m.contains_key("shift")
                || m.contains_key("command")
            {
                log::warn!(
                    "relative_mouse_mode activation marker contains unexpected fields (buttons/alt/ctrl/shift/command). Dropping."
                );
                return;
            }

            // All validation passed - marker will be forwarded as a no-op relative move.
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            crate::keyboard::set_relative_mouse_mode_state(true);
        }

        let alt = m.get("alt").is_some();
        let ctrl = m.get("ctrl").is_some();
        let shift = m.get("shift").is_some();
        let command = m.get("command").is_some();
        let x = m
            .get("x")
            .map(|x| x.parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        let y = m
            .get("y")
            .map(|x| x.parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        let mut mask = 0;
        if let Some(_type) = m.get("type") {
            mask = match _type.as_str() {
                "down" => MOUSE_TYPE_DOWN,
                "up" => MOUSE_TYPE_UP,
                "wheel" => MOUSE_TYPE_WHEEL,
                "trackpad" => MOUSE_TYPE_TRACKPAD,
                "move_relative" => MOUSE_TYPE_MOVE_RELATIVE,
                _ => 0,
            };
        }
        if let Some(buttons) = m.get("buttons") {
            mask |= match buttons.as_str() {
                "left" => MOUSE_BUTTON_LEFT,
                "right" => MOUSE_BUTTON_RIGHT,
                "wheel" => MOUSE_BUTTON_WHEEL,
                "back" => MOUSE_BUTTON_BACK,
                "forward" => MOUSE_BUTTON_FORWARD,
                _ => 0,
            } << 3;
        }
        if let Some(session) = sessions::get_session_by_session_id(&session_id) {
            session.send_mouse(mask, x, y, alt, ctrl, shift, command);
        }
    }
}

pub fn session_restart_remote_device(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.restart_remote_device();
    }
}

pub fn session_get_audit_server_sync(session_id: SessionID, typ: String) -> SyncReturn<String> {
    let res = if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        match session.ensure_trusted_in_process_audit_launch() {
            Ok(_) => session.get_audit_server(typ),
            Err(_) => String::new(),
        }
    } else {
        "".to_owned()
    };
    SyncReturn(res)
}

/// 远程会话通过主界面签发的一次性能力读取连接审计GUID。
pub fn session_read_audit_guid(session_id: SessionID) -> anyhow::Result<String> {
    let session = sessions::get_session_by_session_id(&session_id)
        .ok_or_else(|| anyhow!("远程会话不存在"))?;
    let launch_nonce = session.ensure_trusted_in_process_audit_launch()?;
    let runtime = hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow!("无法启动审计能力运行时"))?;
    runtime.block_on(session.read_audit_guid(launch_nonce))
}

/// 远程会话通过主界面签发的一次性能力写入审计备注。
pub fn session_write_audit_note(
    session_id: SessionID,
    guid: String,
    note: String,
) -> anyhow::Result<()> {
    let session = sessions::get_session_by_session_id(&session_id)
        .ok_or_else(|| anyhow!("远程会话不存在"))?;
    let launch_nonce = session.ensure_trusted_in_process_audit_launch()?;
    let runtime = hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow!("无法启动审计能力运行时"))?;
    runtime.block_on(session.write_audit_note(launch_nonce, guid, note))
}

pub fn session_send_note(session_id: SessionID, note: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        if session.ensure_trusted_in_process_audit_launch().is_ok() {
            session.send_note(note)
        }
    }
}

pub fn session_get_last_audit_note(session_id: SessionID) -> SyncReturn<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.last_audit_note.lock().unwrap().clone())
    } else {
        SyncReturn("".to_owned())
    }
}

pub fn session_set_audit_guid(session_id: SessionID, guid: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        *session.audit_guid.lock().unwrap() = guid;
    }
}

pub fn session_get_audit_guid(session_id: SessionID) -> SyncReturn<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.audit_guid.lock().unwrap().clone())
    } else {
        SyncReturn("".to_owned())
    }
}

pub fn session_get_conn_session_id(session_id: SessionID) -> SyncReturn<String> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        SyncReturn(session.lc.read().unwrap().session_id.to_string())
    } else {
        SyncReturn("".to_owned())
    }
}

pub fn session_alternative_codecs(session_id: SessionID) -> String {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        let (vp8, av1, h264, h265) = session.alternative_codecs();
        let msg = HashMap::from([("vp8", vp8), ("av1", av1), ("h264", h264), ("h265", h265)]);
        serde_json::ser::to_string(&msg).unwrap_or("".to_owned())
    } else {
        String::new()
    }
}

pub fn session_change_prefer_codec(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.update_supported_decodings();
    }
}

pub fn session_on_waiting_for_image_dialog_show(session_id: SessionID) {
    super::flutter::session_on_waiting_for_image_dialog_show(session_id);
}

pub fn session_toggle_virtual_display(session_id: SessionID, index: i32, on: bool) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.toggle_virtual_display(index, on);
        flutter::session_update_virtual_display(&session, index, on);
    }
}

pub fn session_printer_response(
    session_id: SessionID,
    id: i32,
    path: String,
    printer_name: String,
) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.printer_response(id, path, printer_name);
    }
}

pub fn main_set_home_dir(_home: String) {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        *config::APP_HOME_DIR.write().unwrap() = _home;
    }
}

// This is a temporary method to get data dir for ios
pub fn main_get_data_dir_ios(app_dir: String) -> SyncReturn<String> {
    *config::APP_DIR.write().unwrap() = app_dir;
    let data_dir = config::Config::path("data");
    if !data_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            log::warn!("Failed to create data dir {}", e);
        }
    }
    SyncReturn(data_dir.to_string_lossy().to_string())
}

pub fn main_stop_service() {
    #[cfg(target_os = "android")]
    {
        config::Config::set_option("stop-service".into(), "Y".into());
        crate::rendezvous_mediator::RendezvousMediator::restart();
    }
}

pub fn main_start_service() {
    #[cfg(target_os = "android")]
    {
        config::Config::set_option("stop-service".into(), "".into());
        crate::rendezvous_mediator::reset_needs_deploy_notification();
        crate::rendezvous_mediator::RendezvousMediator::restart();
    }
}

pub fn main_update_temporary_password() {
    update_temporary_password();
}

pub fn main_check_super_user_permission() -> bool {
    check_super_user_permission()
}

pub fn main_get_unlock_pin() -> SyncReturn<String> {
    SyncReturn(get_unlock_pin())
}

pub fn main_set_unlock_pin(pin: String) -> SyncReturn<String> {
    SyncReturn(set_unlock_pin(pin))
}

pub fn main_check_mouse_time() {
    check_mouse_time();
}

pub fn main_get_mouse_time() -> f64 {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        get_mouse_time()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        0.0
    }
}

pub fn main_wol(id: String) {
    // TODO: move send_wol outside.
    #[cfg(not(any(target_os = "ios")))]
    crate::lan::send_wol(id)
}

pub fn main_create_shortcut(_id: String) {
    #[cfg(windows)]
    create_shortcut(_id);
}

pub fn cm_send_chat(conn_id: i32, msg: String) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::send_chat(conn_id, msg);
}

pub fn cm_login_res(conn_id: i32, res: bool) {
    #[cfg(not(any(target_os = "ios")))]
    if res {
        crate::ui_cm_interface::authorize(conn_id);
    } else {
        crate::ui_cm_interface::close(conn_id);
    }
}

pub fn cm_close_connection(conn_id: i32) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::close(conn_id);
}

pub fn cm_remove_disconnected_connection(conn_id: i32) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::remove(conn_id);
}

pub fn cm_check_click_time(conn_id: i32) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::check_click_time(conn_id)
}

pub fn cm_get_click_time() -> f64 {
    #[cfg(not(any(target_os = "ios")))]
    return crate::ui_cm_interface::get_click_time() as _;
    #[cfg(any(target_os = "ios"))]
    return 0 as _;
}

pub fn cm_switch_permission(conn_id: i32, name: String, enabled: bool) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::switch_permission(conn_id, name, enabled)
}

pub fn cm_can_elevate() -> SyncReturn<bool> {
    SyncReturn(crate::ui_cm_interface::can_elevate())
}

pub fn cm_elevate_portable(conn_id: i32) {
    #[cfg(not(any(target_os = "ios")))]
    crate::ui_cm_interface::elevate_portable(conn_id);
}

pub fn cm_switch_back(conn_id: i32) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    crate::ui_cm_interface::switch_back(conn_id);
}

pub fn cm_get_config(name: String) -> String {
    #[cfg(not(target_os = "ios"))]
    {
        if let Ok(Some(v)) = crate::ipc::get_config(&name) {
            v
        } else {
            "".to_string()
        }
    }
    #[cfg(target_os = "ios")]
    {
        "".to_string()
    }
}

pub fn main_get_build_date() -> String {
    crate::BUILD_DATE.to_string()
}

pub fn translate(name: String, locale: String) -> SyncReturn<String> {
    SyncReturn(crate::client::translate_locale(name, &locale))
}

pub fn session_get_rgba_size(session_id: SessionID, display: usize) -> SyncReturn<usize> {
    SyncReturn(super::flutter::session_get_rgba_size(session_id, display))
}

pub fn session_next_rgba(session_id: SessionID, display: usize) -> SyncReturn<()> {
    SyncReturn(super::flutter::session_next_rgba(session_id, display))
}

pub fn session_register_pixelbuffer_texture(
    session_id: SessionID,
    display: usize,
    ptr: usize,
) -> SyncReturn<()> {
    SyncReturn(super::flutter::session_register_pixelbuffer_texture(
        session_id, display, ptr,
    ))
}

pub fn session_register_gpu_texture(
    session_id: SessionID,
    display: usize,
    ptr: usize,
) -> SyncReturn<()> {
    SyncReturn(super::flutter::session_register_gpu_texture(
        session_id, display, ptr,
    ))
}

pub fn query_onlines(ids: Vec<String>) {
    let _ = flutter::async_tasks::query_onlines(ids);
}

pub fn version_to_number(v: String) -> SyncReturn<i64> {
    SyncReturn(hbb_common::get_version_number(&v))
}

pub fn option_synced() -> bool {
    crate::ui_interface::option_synced()
}

pub fn main_is_installed() -> SyncReturn<bool> {
    SyncReturn(is_installed())
}

pub fn main_init_input_source() -> SyncReturn<()> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    crate::keyboard::input_source::init_input_source();
    SyncReturn(())
}

pub fn main_is_installed_lower_version() -> SyncReturn<bool> {
    SyncReturn(is_installed_lower_version())
}

pub fn main_is_installed_daemon(prompt: bool) -> SyncReturn<bool> {
    SyncReturn(is_installed_daemon(prompt))
}

pub fn main_is_process_trusted(prompt: bool) -> SyncReturn<bool> {
    SyncReturn(is_process_trusted(prompt))
}

pub fn main_is_can_screen_recording(prompt: bool) -> SyncReturn<bool> {
    SyncReturn(is_can_screen_recording(prompt))
}

pub fn main_is_can_input_monitoring(prompt: bool) -> SyncReturn<bool> {
    SyncReturn(is_can_input_monitoring(prompt))
}

pub fn main_is_share_rdp() -> SyncReturn<bool> {
    SyncReturn(is_share_rdp())
}

pub fn main_set_share_rdp(enable: bool) {
    set_share_rdp(enable)
}

pub fn main_goto_install() -> SyncReturn<bool> {
    goto_install();
    SyncReturn(true)
}

pub fn main_get_new_version() -> SyncReturn<String> {
    SyncReturn(get_new_version())
}

pub fn main_update_me() -> SyncReturn<bool> {
    update_me("".to_owned());
    SyncReturn(true)
}

pub fn set_cur_session_id(session_id: SessionID) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        set_cur_session_id_(session_id, &session.get_keyboard_mode())
    }
}

fn set_cur_session_id_(session_id: SessionID, _keyboard_mode: &str) {
    super::flutter::set_cur_session_id(session_id);
    #[cfg(windows)]
    crate::keyboard::update_grab_get_key_name(_keyboard_mode);
}

pub fn install_show_run_without_install() -> SyncReturn<bool> {
    SyncReturn(show_run_without_install())
}

pub fn install_run_without_install() {
    run_without_install();
}

pub fn install_install_me(options: String, path: String) {
    install_me(options, path, false, false);
}

pub fn install_install_path() -> SyncReturn<String> {
    SyncReturn(install_path())
}

pub fn install_install_options() -> SyncReturn<String> {
    SyncReturn(install_options())
}

pub fn main_account_auth(op: String, remember_me: bool) -> anyhow::Result<String> {
    let id = get_id();
    let uuid = get_uuid();
    let attempt = account_auth(op, id, uuid, remember_me)?;
    auth_binding::serialize_auth_attempt(&attempt)
}

pub fn main_account_auth_cancel(attempt_json: String) -> anyhow::Result<bool> {
    let attempt = parse_auth_attempt(&attempt_json)?;
    crate::hbbs_http::account::OidcSession::auth_cancel_attempt(&attempt)
}

pub fn main_account_auth_result(attempt_json: String) -> anyhow::Result<String> {
    let attempt = parse_auth_attempt(&attempt_json)?;
    let result = crate::hbbs_http::account::OidcSession::get_result_for_attempt(&attempt)
        .ok_or_else(|| anyhow!("OIDC 登录请求已失效"))?;
    serde_json::to_string(&result).map_err(|_| anyhow!("无法序列化 OIDC 登录结果"))
}

pub fn main_on_main_window_close() {
    // may called more than one times
    #[cfg(windows)]
    crate::portable_service::client::drop_portable_service_shared_memory();
}

pub fn main_current_is_wayland() -> SyncReturn<bool> {
    SyncReturn(current_is_wayland())
}

pub fn main_is_login_wayland() -> SyncReturn<bool> {
    SyncReturn(is_login_wayland())
}

pub fn main_hide_dock() -> SyncReturn<bool> {
    #[cfg(target_os = "macos")]
    crate::platform::macos::hide_dock();
    SyncReturn(true)
}

pub fn main_has_file_clipboard() -> SyncReturn<bool> {
    let ret = cfg!(any(target_os = "windows", feature = "unix-file-copy-paste",));
    SyncReturn(ret)
}

pub fn main_has_gpu_texture_render() -> SyncReturn<bool> {
    SyncReturn(cfg!(feature = "vram"))
}

pub fn cm_init() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    crate::flutter::connection_manager::cm_init();
}

/// Start an ipc server for receiving the url scheme.
///
/// * Should only be called in the main flutter window.
/// * macOS only
pub fn main_start_ipc_url_server() {
    #[cfg(target_os = "macos")]
    std::thread::spawn(move || crate::server::start_ipc_url_server());
}

pub fn main_test_wallpaper(_second: u64) {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    std::thread::spawn(move || match crate::platform::WallPaperRemover::new() {
        Ok(_remover) => {
            std::thread::sleep(std::time::Duration::from_secs(_second));
        }
        Err(e) => {
            log::info!("create wallpaper remover failed: {:?}", e);
        }
    });
}

pub fn main_support_remove_wallpaper() -> bool {
    support_remove_wallpaper()
}

pub fn is_incoming_only() -> SyncReturn<bool> {
    SyncReturn(config::is_incoming_only())
}

pub fn is_outgoing_only() -> SyncReturn<bool> {
    SyncReturn(config::is_outgoing_only())
}

pub fn is_custom_client() -> SyncReturn<bool> {
    SyncReturn(crate::common::is_custom_client())
}

pub fn is_disable_settings() -> SyncReturn<bool> {
    SyncReturn(config::is_disable_settings())
}

pub fn is_disable_ab() -> SyncReturn<bool> {
    SyncReturn(config::is_disable_ab())
}

pub fn is_disable_account() -> SyncReturn<bool> {
    SyncReturn(config::is_disable_account())
}

pub fn is_disable_group_panel() -> SyncReturn<bool> {
    SyncReturn(LocalConfig::get_option("disable-group-panel") == "Y")
}

// windows only
pub fn is_disable_installation() -> SyncReturn<bool> {
    SyncReturn(config::is_disable_installation())
}

pub fn is_preset_password() -> bool {
    // On desktop, service owns the authoritative config; query it via IPC and return only a boolean.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return crate::ipc::is_permanent_password_preset();

    // On mobile, we have no service IPC; verify against local storage.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return config::Config::is_using_preset_password();
}

// Don't call this function for desktop version.
// We need this function because we want a sync return for mobile version.
pub fn is_preset_password_mobile_only() -> SyncReturn<bool> {
    SyncReturn(is_preset_password())
}

/// Send a url scheme through the ipc.
///
/// * macOS only
#[allow(unused_variables)]
pub fn send_url_scheme(_url: String) {
    #[cfg(target_os = "macos")]
    std::thread::spawn(move || crate::handle_url_scheme(_url));
}

#[inline]
pub fn plugin_event(_id: String, _peer: String, _event: Vec<u8>) {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(crate::plugin::handle_ui_event(&_id, &_peer, &_event));
    }
}

pub fn plugin_register_event_stream(_id: String, _event2ui: StreamSink<EventToUI>) {
    #[cfg(feature = "plugin_framework")]
    {
        crate::plugin::native_handlers::session::session_register_event_stream(_id, _event2ui);
    }
}

#[inline]
pub fn plugin_get_session_option(
    _id: String,
    _peer: String,
    _key: String,
) -> SyncReturn<Option<String>> {
    if crate::client::protected_peer_option_key(&_key) {
        return SyncReturn(None);
    }
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        SyncReturn(crate::plugin::PeerConfig::get(&_id, &_peer, &_key))
    }
    #[cfg(any(
        not(feature = "plugin_framework"),
        target_os = "android",
        target_os = "ios"
    ))]
    {
        SyncReturn(None)
    }
}

#[inline]
pub fn plugin_set_session_option(_id: String, _peer: String, _key: String, _value: String) {
    if crate::client::protected_peer_option_key(&_key) {
        log::warn!("插件会话配置拒绝写入受保护的密码来源标记");
        return;
    }
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _res = crate::plugin::PeerConfig::set(&_id, &_peer, &_key, &_value);
    }
}

#[inline]
pub fn plugin_get_shared_option(_id: String, _key: String) -> SyncReturn<Option<String>> {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        SyncReturn(crate::plugin::ipc::get_config(&_id, &_key).unwrap_or(None))
    }
    #[cfg(any(
        not(feature = "plugin_framework"),
        target_os = "android",
        target_os = "ios"
    ))]
    {
        SyncReturn(None)
    }
}

#[inline]
pub fn plugin_set_shared_option(_id: String, _key: String, _value: String) {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(crate::plugin::ipc::set_config(&_id, &_key, _value));
    }
}

#[inline]
pub fn plugin_reload(_id: String) {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(crate::plugin::ipc::reload_plugin(&_id,));
        allow_err!(crate::plugin::reload_plugin(&_id));
    }
}

#[inline]
pub fn plugin_enable(_id: String, _v: bool) -> SyncReturn<()> {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(crate::plugin::ipc::set_manager_plugin_config(
            &_id,
            "enabled",
            _v.to_string()
        ));
        if _v {
            allow_err!(crate::plugin::load_plugin(&_id));
        } else {
            crate::plugin::unload_plugin(&_id);
        }
    }
    SyncReturn(())
}

pub fn plugin_is_enabled(_id: String) -> SyncReturn<bool> {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        SyncReturn(
            match crate::plugin::ipc::get_manager_plugin_config(&_id, "enabled") {
                Ok(Some(enabled)) => bool::from_str(&enabled).unwrap_or(false),
                _ => false,
            },
        )
    }
    #[cfg(any(
        not(feature = "plugin_framework"),
        target_os = "android",
        target_os = "ios"
    ))]
    {
        SyncReturn(false)
    }
}

pub fn plugin_feature_is_enabled() -> SyncReturn<bool> {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        #[cfg(debug_assertions)]
        let enabled = true;
        #[cfg(not(debug_assertions))]
        let enabled = is_installed();
        SyncReturn(enabled)
    }
    #[cfg(any(
        not(feature = "plugin_framework"),
        target_os = "android",
        target_os = "ios"
    ))]
    {
        SyncReturn(false)
    }
}

pub fn plugin_sync_ui(_sync_to: String) {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if plugin_feature_is_enabled().0 {
            crate::plugin::sync_ui(_sync_to);
        }
    }
}

pub fn plugin_list_reload() {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        crate::plugin::load_plugin_list();
    }
}

pub fn plugin_install(_id: String, _b: bool) {
    #[cfg(feature = "plugin_framework")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if _b {
            if let Err(e) = crate::plugin::install_plugin(&_id) {
                log::error!("Failed to install plugin '{}': {}", _id, e);
            }
        } else {
            crate::plugin::uninstall_plugin(&_id, true);
        }
    }
}

pub fn is_support_multi_ui_session(version: String) -> SyncReturn<bool> {
    SyncReturn(crate::common::is_support_multi_ui_session(&version))
}

pub fn is_selinux_enforcing() -> SyncReturn<bool> {
    #[cfg(target_os = "linux")]
    {
        SyncReturn(crate::platform::linux::is_selinux_enforcing())
    }
    #[cfg(not(target_os = "linux"))]
    {
        SyncReturn(false)
    }
}

pub fn main_default_privacy_mode_impl() -> SyncReturn<String> {
    SyncReturn(crate::privacy_mode::DEFAULT_PRIVACY_MODE_IMPL.to_owned())
}

pub fn main_supported_privacy_mode_impls() -> SyncReturn<String> {
    SyncReturn(
        serde_json::to_string(&crate::privacy_mode::get_supported_privacy_mode_impl())
            .unwrap_or_default(),
    )
}

pub fn main_supported_input_source() -> SyncReturn<String> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        SyncReturn("".to_owned())
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        SyncReturn(
            serde_json::to_string(&crate::keyboard::input_source::get_supported_input_source())
                .unwrap_or_default(),
        )
    }
}

pub fn main_generate2fa() -> String {
    generate2fa()
}

pub fn main_verify2fa(code: String) -> bool {
    verify2fa(code)
}

pub fn main_has_valid_2fa_sync() -> SyncReturn<bool> {
    SyncReturn(has_valid_2fa())
}

pub fn main_verify_bot(token: String) -> String {
    verify_bot(token)
}

pub fn main_has_valid_bot_sync() -> SyncReturn<bool> {
    SyncReturn(has_valid_bot())
}

pub fn main_get_hard_option(key: String) -> SyncReturn<String> {
    SyncReturn(get_hard_option(key))
}

pub fn main_get_buildin_option(key: String) -> SyncReturn<String> {
    SyncReturn(get_builtin_option(&key))
}

pub fn main_check_hwcodec() {
    check_hwcodec()
}

pub fn main_get_trusted_devices() -> String {
    get_trusted_devices()
}

pub fn main_remove_trusted_devices(json: String) {
    remove_trusted_devices(&json)
}

pub fn main_clear_trusted_devices() {
    clear_trusted_devices()
}

pub fn main_max_encrypt_len() -> SyncReturn<usize> {
    SyncReturn(max_encrypt_len())
}

pub fn session_request_new_display_init_msgs(session_id: SessionID, display: usize) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.request_init_msgs(display);
    }
}

pub fn main_audio_support_loopback() -> SyncReturn<bool> {
    #[cfg(target_os = "windows")]
    let is_surpport = true;
    #[cfg(feature = "screencapturekit")]
    let is_surpport = crate::audio_service::is_screen_capture_kit_available();
    #[cfg(not(any(target_os = "windows", feature = "screencapturekit")))]
    let is_surpport = false;
    SyncReturn(is_surpport)
}

pub fn main_get_printer_names() -> SyncReturn<String> {
    #[cfg(target_os = "windows")]
    return SyncReturn(
        serde_json::to_string(&crate::platform::windows::get_printer_names().unwrap_or_default())
            .unwrap_or_default(),
    );
    #[cfg(not(target_os = "windows"))]
    return SyncReturn("".to_owned());
}

pub fn main_get_common(key: String) -> String {
    if key == "is-printer-installed" {
        #[cfg(target_os = "windows")]
        {
            return match remote_printer::is_rd_printer_installed(&get_app_name()) {
                Ok(r) => r.to_string(),
                Err(e) => e.to_string(),
            };
        }
        #[cfg(not(target_os = "windows"))]
        return false.to_string();
    } else if key == "is-support-printer-driver" {
        #[cfg(target_os = "windows")]
        return crate::platform::is_win_10_or_greater().to_string();
        #[cfg(not(target_os = "windows"))]
        return false.to_string();
    } else if key == "transfer-job-id" {
        return hbb_common::fs::get_next_job_id().to_string();
    } else if key == "is-remote-modify-enabled-by-control-permissions" {
        return match is_remote_modify_enabled_by_control_permissions() {
            Some(true) => "true",
            Some(false) => "false",
            None => "",
        }
        .to_string();
    } else if key == "has-gnome-shortcuts-inhibitor-permission" {
        #[cfg(target_os = "linux")]
        return crate::platform::linux::has_gnome_shortcuts_inhibitor_permission().to_string();
        #[cfg(not(target_os = "linux"))]
        return false.to_string();
    } else if key == "permanent-password-set" {
        return ui_interface::is_permanent_password_set().to_string();
    } else if key == "local-permanent-password-set" {
        return ui_interface::is_local_permanent_password_set().to_string();
    } else {
        if key.starts_with("download-data-") {
            let id = key.replace("download-data-", "");
            match crate::hbbs_http::downloader::get_download_data(&id) {
                Ok(data) => serde_json::to_string(&data).unwrap_or_default(),
                Err(e) => {
                    format!("error:{}", e)
                }
            }
        } else if key.starts_with("download-file-") {
            let _version = key.replace("download-file-", "");
            #[cfg(target_os = "windows")]
            return match (
                crate::platform::windows::is_msi_installed(),
                crate::common::is_custom_client(),
            ) {
                (Ok(true), false) => format!("rustdesk-{_version}-x86_64.msi"),
                (Ok(true), true) | (Ok(false), _) => format!("rustdesk-{_version}-x86_64.exe"),
                (Err(e), _) => {
                    log::error!("Failed to check if is msi: {}", e);
                    format!("error:update-failed-check-msi-tip")
                }
            };
            #[cfg(target_os = "macos")]
            {
                return if cfg!(target_arch = "x86_64") {
                    format!("rustdesk-{_version}-x86_64.dmg")
                } else if cfg!(target_arch = "aarch64") {
                    format!("rustdesk-{_version}-aarch64.dmg")
                } else {
                    "error:unsupported".to_owned()
                };
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                "error:unsupported".to_owned()
            }
        } else {
            "".to_owned()
        }
    }
}

pub fn main_get_common_sync(key: String) -> SyncReturn<String> {
    SyncReturn(main_get_common(key))
}

pub fn main_set_common(_key: String, _value: String) {
    #[cfg(target_os = "windows")]
    if _key == "install-printer" && crate::platform::is_win_10_or_greater() {
        std::thread::spawn(move || {
            let (success, msg) = match remote_printer::install_update_printer(&get_app_name()) {
                Ok(_) => (true, "".to_owned()),
                Err(e) => {
                    let err = e.to_string();
                    log::error!("Failed to install/update rd printer: {}", &err);
                    (false, err)
                }
            };
            if success {
                // Use `ipc` to notify the server process to update the install option in the registry.
                // Because `install_update_printer()` may prompt for permissions, there is no need to prompt again here.
                if let Err(e) = crate::ipc::set_install_option(
                    crate::platform::REG_NAME_INSTALL_PRINTER.to_string(),
                    "1".to_string(),
                ) {
                    log::error!("Failed to set install printer option: {}", e);
                }
            }
            let data = HashMap::from([
                ("name", serde_json::json!("install-printer-res")),
                ("success", serde_json::json!(success)),
                ("msg", serde_json::json!(msg)),
            ]);
            let _res = flutter::push_global_event(
                flutter::APP_TYPE_MAIN,
                serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
            );
        });
    }
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        use crate::updater::get_download_file_from_url;
        if _key == "download-new-version" {
            let download_url = _value.clone();
            let event_key = "download-new-version".to_owned();
            let data = if let Some(download_file) = get_download_file_from_url(&download_url) {
                std::fs::remove_file(&download_file).ok();
                match crate::hbbs_http::downloader::download_file(
                    download_url,
                    Some(PathBuf::from(download_file)),
                    Some(Duration::from_secs(3)),
                ) {
                    Ok(id) => HashMap::from([("name", event_key), ("id", id)]),
                    Err(e) => HashMap::from([("name", event_key), ("error", e.to_string())]),
                }
            } else {
                HashMap::from([
                    ("name", event_key),
                    ("error", "Invalid download url".to_string()),
                ])
            };
            let _res = flutter::push_global_event(
                flutter::APP_TYPE_MAIN,
                serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
            );
        } else if _key == "update-me" {
            if let Some(new_version_file) = get_download_file_from_url(&_value) {
                log::debug!(
                    "New version file is downloaded, update begin, {:?}",
                    new_version_file.to_str()
                );
                if let Some(f) = new_version_file.to_str() {
                    // 1.4.0 does not support "--update"
                    // But we can assume that the new version supports it.

                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                    match crate::platform::update_to(f) {
                        Ok(_) => {
                            log::info!("Update process is launched successfully!");
                        }
                        Err(e) => {
                            log::error!("Failed to update to new version, {}", e);
                            fs::remove_file(f).ok();
                        }
                    }
                }
            }
        } else if _key == "extract-update-dmg" {
            #[cfg(target_os = "macos")]
            {
                if let Some(new_version_file) = get_download_file_from_url(&_value) {
                    if let Some(f) = new_version_file.to_str() {
                        crate::platform::macos::extract_update_dmg(f);
                    } else {
                        // unreachable!()
                        log::error!("Failed to get the new version file path");
                    }
                } else {
                    // unreachable!()
                    log::error!("Failed to get the new version file from url: {}", _value);
                }
            }
        }
    }

    if _key == "remove-downloader" {
        crate::hbbs_http::downloader::remove(&_value);
    } else if _key == "cancel-downloader" {
        crate::hbbs_http::downloader::cancel(&_value);
    }

    #[cfg(target_os = "linux")]
    if _key == "clear-gnome-shortcuts-inhibitor-permission" {
        std::thread::spawn(move || {
            let (success, msg) =
                match crate::platform::linux::clear_gnome_shortcuts_inhibitor_permission() {
                    Ok(_) => (true, "".to_owned()),
                    Err(e) => (false, e.to_string()),
                };
            let data = HashMap::from([
                (
                    "name",
                    serde_json::json!("clear-gnome-shortcuts-inhibitor-permission-res"),
                ),
                ("success", serde_json::json!(success)),
                ("msg", serde_json::json!(msg)),
            ]);
            let _res = flutter::push_global_event(
                flutter::APP_TYPE_MAIN,
                serde_json::ser::to_string(&data).unwrap_or("".to_owned()),
            );
        });
    }
}

pub fn session_get_common_sync(
    session_id: SessionID,
    key: String,
    param: String,
) -> SyncReturn<Option<String>> {
    SyncReturn(session_get_common(session_id, key, param))
}

pub fn session_get_common(
    session_id: SessionID,
    key: String,
    #[allow(unused_variables)] param: String,
) -> Option<String> {
    if let Some(s) = sessions::get_session_by_session_id(&session_id) {
        let v = if key == "is_screenshot_supported" {
            s.is_screenshot_supported().to_string()
        } else {
            "".to_owned()
        };
        Some(v)
    } else {
        None
    }
}

#[cfg(target_os = "android")]
pub mod server_side {
    use hbb_common::{config, log};
    use jni::{
        errors::{Error as JniError, Result as JniResult},
        objects::{JClass, JObject, JString},
        sys::{jboolean, jstring},
        JNIEnv,
    };

    use crate::start_server;

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_startServer(
        env: JNIEnv,
        _class: JClass,
        app_dir: JString,
        custom_client_config: JString,
    ) {
        log::debug!("startServer from jvm");
        let mut env = env;
        if let Ok(app_dir) = env.get_string(&app_dir) {
            *config::APP_DIR.write().unwrap() = app_dir.into();
        }
        if let Ok(custom_client_config) = env.get_string(&custom_client_config) {
            if !custom_client_config.is_empty() {
                let custom_client_config: String = custom_client_config.into();
                crate::read_custom_client(&custom_client_config);
            }
        }
        std::thread::spawn(move || start_server(true));
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_startService(_env: JNIEnv, _class: JClass) {
        log::debug!("startService from jvm");
        config::Config::set_option("stop-service".into(), "".into());
        crate::rendezvous_mediator::reset_needs_deploy_notification();
        crate::rendezvous_mediator::RendezvousMediator::restart();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_translateLocale(
        env: JNIEnv,
        _class: JClass,
        locale: JString,
        input: JString,
    ) -> jstring {
        let mut env = env;
        let res = if let (Ok(input), Ok(locale)) = (env.get_string(&input), env.get_string(&locale))
        {
            let input: String = input.into();
            let locale: String = locale.into();
            crate::client::translate_locale(input, &locale)
        } else {
            "".into()
        };
        return env.new_string(res).unwrap_or(input).into_raw();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_refreshScreen(_env: JNIEnv, _class: JClass) {
        crate::server::video_service::refresh()
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_getLocalOption(
        env: JNIEnv,
        _class: JClass,
        key: JString,
    ) -> jstring {
        let mut env = env;
        let res = if let Ok(key) = env.get_string(&key) {
            let key: String = key.into();
            if super::protected_auth_bridge_key(&key) {
                String::new()
            } else {
                super::get_local_option(key)
            }
        } else {
            "".into()
        };
        return env.new_string(res).unwrap_or_default().into_raw();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_getBuildinOption(
        env: JNIEnv,
        _class: JClass,
        key: JString,
    ) -> jstring {
        let mut env = env;
        let res = if let Ok(key) = env.get_string(&key) {
            let key: String = key.into();
            super::get_builtin_option(&key)
        } else {
            "".into()
        };
        return env.new_string(res).unwrap_or_default().into_raw();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ffi_FFI_isServiceClipboardEnabled(
        env: JNIEnv,
        _class: JClass,
    ) -> jboolean {
        jboolean::from(crate::server::is_clipboard_service_ok())
    }
}

#[cfg(test)]
mod issue9_ffi_tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn auth_attempt() -> AuthAttempt {
        AuthAttempt {
            attempt_id: 7,
            nonce: "issue9-attempt-nonce".to_owned(),
            normalized_api_base: "https://example.com".to_owned(),
            logout_generation: 3,
        }
    }

    #[test]
    fn 登录请求能力拒绝未知字段和空_nonce() {
        let mut value = serde_json::to_value(auth_attempt()).unwrap();
        value["unexpected"] = Value::Bool(true);
        assert!(parse_auth_attempt(&value.to_string()).is_err());

        value.as_object_mut().unwrap().remove("unexpected");
        value["nonce"] = Value::String(String::new());
        assert!(parse_auth_attempt(&value.to_string()).is_err());
    }

    struct PersonalHashTestRoot(PathBuf);

    impl PersonalHashTestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustdesk-personal-hash-observer-{}",
                hbb_common::uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("应创建 personal hash 测试目录");
            Self(path)
        }
    }

    impl Drop for PersonalHashTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct StoredPeerConfig(String);

    impl StoredPeerConfig {
        fn new() -> Self {
            Self(format!(
                "issue9-flutter-peer-dto-{}",
                hbb_common::uuid::Uuid::new_v4()
            ))
        }
    }

    impl Drop for StoredPeerConfig {
        fn drop(&mut self) {
            PeerConfig::remove(&self.0);
        }
    }

    fn authenticated_personal_hash_binding(
        root: &PersonalHashTestRoot,
    ) -> auth_binding::AuthBinding {
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(&root.0, b"personal-hash-observer-install")
                .expect("应创建 personal hash 测试 authority");
        let mut binding = auth_binding::AuthBinding::open(authority).expect("应打开认证状态");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始测试登录");
        binding
            .commit_auth_attempt(
                &attempt,
                "test-token".to_owned(),
                AuthSafeUser {
                    id: Some(1),
                    name: "alice".to_owned(),
                    display_name: "Alice".to_owned(),
                    avatar: String::new(),
                    email: String::new(),
                    note: String::new(),
                    status: 1,
                    is_admin: false,
                    verifier: String::new(),
                },
                None,
            )
            .expect("应提交测试登录");
        binding
    }

    fn observe_current_personal_hash_response(
        binding: &mut auth_binding::AuthBinding,
        handle: &CredentialedRequestHandle,
        operation: FfiSessionOperation,
        target: &str,
        status: u16,
        content_type: Option<&str>,
        body: &str,
    ) -> ResultType<Option<String>> {
        let request_fence = binding.personal_hash_request_fence(handle)?;
        observe_native_personal_hash_response_with(
            binding,
            handle,
            request_fence,
            operation,
            target,
            status,
            content_type,
            body,
        )
    }

    #[test]
    fn 通用选项桥隐藏认证保留键() {
        let filtered = filter_protected_options(
            json!({
                "access_token": "secret",
                "user_info": "{\"name\":\"alice\"}",
                "cursor": "42",
                "theme": "dark"
            })
            .to_string(),
        );
        let value: Value = serde_json::from_str(&filtered).unwrap();
        assert_eq!(value, json!({"theme": "dark"}));
        assert!(protected_auth_bridge_key("ACCESS_TOKEN"));
        assert!(!protected_auth_bridge_key("theme"));
        for key in [
            "api-server",
            "custom-rendezvous-server",
            "relay-server",
            "key",
        ] {
            assert!(protected_generic_write_key(key), "{key}");
        }
    }

    #[test]
    fn flutter_对端配置_dto_从不返回密码或来源标记() {
        for explicit in [false, true] {
            let peer = StoredPeerConfig::new();
            let secret = if explicit {
                b"explicit-password-material".to_vec()
            } else {
                b"legacy-unmarked-password-material".to_vec()
            };
            let mut seeded = PeerConfig {
                password: secret.clone(),
                ..Default::default()
            };
            if explicit {
                crate::client::mark_peer_config_password_explicit_for_test(&mut seeded);
            }
            seeded.options.insert(
                " PeEr-PASSWORD-Provenance ".to_owned(),
                "forged-history-value".to_owned(),
            );
            seeded.store(&peer.0);

            let SyncReturn(serialized) = main_get_peer_sync(peer.0.clone());
            assert!(!serialized.contains("peer-password-provenance"));
            assert!(!serialized.contains("PeEr-PASSWORD-Provenance"));
            let returned: Value = serde_json::from_str(&serialized).expect("Flutter DTO 应可解析");
            let top = returned.as_object().expect("Flutter DTO 顶层应为对象");
            assert_eq!(top.len(), 2);
            assert!(top.contains_key("info"));
            assert!(top.contains_key("port_forwards"));
            assert_eq!(
                top["info"]
                    .as_object()
                    .expect("info 应为对象")
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["hostname"]
            );
            assert_eq!(top["port_forwards"], json!([]));
        }
    }

    #[test]
    fn 地址簿同步只导出显式记住的对端密码() {
        let password = b"explicit-user-password".to_vec();
        let unmarked = PeerConfig {
            password: password.clone(),
            ..Default::default()
        };
        assert!(ui_interface::peer_to_map("100001".to_owned(), unmarked)["hash"].is_empty());

        let mut explicit = PeerConfig {
            password,
            ..Default::default()
        };
        crate::client::mark_peer_config_password_explicit_for_test(&mut explicit);
        assert!(!ui_interface::peer_to_map("100001".to_owned(), explicit)["hash"].is_empty());
    }

    #[test]
    fn 严格请求拒绝_dart_凭证头() {
        for name in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
        ] {
            let headers = format!(r#"{{"{name}":"sentinel"}}"#);
            assert!(parse_strict_headers(&headers).is_err());
        }
        assert!(parse_strict_headers("{\"X-Safe\":\"ok\\r\\nCookie: sentinel\"}").is_err());
        assert_eq!(
            parse_strict_headers(r#"{"Content-Type":"application/json"}"#).unwrap(),
            vec![("Content-Type".to_owned(), "application/json".to_owned())]
        );
    }

    #[test]
    fn 通用_http_只接受无凭证_json_请求头() {
        assert!(ui_interface::generic_http_headers_are_allowed(
            r#"{"Content-Type":"application/json","Accept":"application/json"}"#
        ));
        for headers in [
            r#"{"Authorization":"Bearer sentinel"}"#,
            r#"{"Proxy-Authorization":"sentinel"}"#,
            r#"{"Cookie":"sentinel"}"#,
            r#"{"Set-Cookie":"sentinel"}"#,
            r#"{"Host":"attacker.example"}"#,
            "{\"X-Safe\":\"value\\r\\nAuthorization: Bearer sentinel\"}",
            "Authorization: Bearer sentinel",
        ] {
            assert!(
                !ui_interface::generic_http_headers_are_allowed(headers),
                "{headers}"
            );
        }
    }

    #[test]
    fn 登录安全用户拒绝超范围_id() {
        let invalid = json!({
            "id": ISSUE9_MAX_SAFE_INTEGER + 1,
            "name": "alice"
        });
        assert!(parse_safe_auth_user(&invalid).is_err());
    }

    #[test]
    fn 用户桥只序列化显式白名单字段() {
        let verifier = "issue9-verifier-sentinel";
        let safe_user = AuthSafeUser {
            id: Some(7),
            name: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            avatar: "avatar".to_owned(),
            email: "alice@example.com".to_owned(),
            note: "visible-note".to_owned(),
            status: 1,
            is_admin: true,
            verifier: verifier.to_owned(),
        };
        let snapshot = AuthSnapshot {
            revision: 1,
            auth_epoch: 2,
            logout_generation: 3,
            pending_logout_count: 0,
            session: Some(AuthSessionSnapshot {
                normalized_api_base: "https://example.com".to_owned(),
                namespace: "id:7".to_owned(),
                subject: crate::hbbs_http::auth_state_store::AuthSubject::UserId(7),
                cursor_key: "cursor-key".to_owned(),
                cursor: 4,
                capability: AddressBookCapability::Issue9V2,
                force_full_pending: false,
                is_pro: false,
                session_epoch: 2,
                session_nonce: "nonce".to_owned(),
                safe_user: safe_user.clone(),
            }),
            corrupt: false,
        };

        let serialized = serialize_auth_snapshot(&snapshot).expect("应序列化认证快照");
        let value: Value = serde_json::from_str(&serialized).unwrap();
        let user = &value["session"]["safe_user"];
        assert_eq!(user["email"], "alice@example.com");
        assert_eq!(user["note"], "visible-note");
        assert!(user.get("verifier").is_none());
        assert!(!serialized.contains(verifier));
        assert!(!format!("{safe_user:?}").contains(verifier));

        let current_user = sanitize_current_user_response(
            &json!({
                "id": 7,
                "name": "alice",
                "display_name": "Alice",
                "email": "alice@example.com",
                "note": "visible-note",
                "verifier": verifier,
                "info": {"other": {"secret": verifier}},
                "third_auth_type": verifier
            })
            .to_string(),
        )
        .expect("应清理当前用户响应");
        let current_user_value: Value = serde_json::from_str(&current_user).unwrap();
        assert_eq!(current_user_value["name"], "alice");
        assert_eq!(current_user_value["email"], "alice@example.com");
        assert!(current_user_value.get("verifier").is_none());
        assert!(!current_user.contains(verifier));
    }

    #[test]
    fn 个人地址簿_peer_严格解码并拒绝非法字段() {
        let encoded = STANDARD.encode(b"decoded-hash");
        let parsed = parse_personal_hash_peer_items(&json!([
            {"id": "100001", "hash": encoded},
            {"id": "100002", "hash": null}
        ]))
        .expect("应解析合法 personal hash 列表");
        assert_eq!(
            parsed[0],
            ("100001".to_owned(), Some(b"decoded-hash".to_vec()))
        );
        assert_eq!(parsed[1], ("100002".to_owned(), None));

        assert!(parse_personal_hash_peer_items(&json!([
            {"id": "100001", "hash": 42}
        ]))
        .is_err());
        assert!(parse_personal_hash_peer_items(&json!([
            {"id": "100001", "hash": "%%%"}
        ]))
        .is_err());
        assert!(parse_commercial_personal_page_query(
            "https://example.com/api/ab/peers?current=1&pageSize=100&ab=shared&ab=personal"
        )
        .is_err());
        assert!(parse_commercial_personal_page_query(
            "https://example.com/api/ab/peers?current=1&pageSize=100&ab=personal&extra=1"
        )
        .is_err());
    }

    #[test]
    fn native_legacy_observer_签发回执且坏响应立即清空旧表() {
        let root = PersonalHashTestRoot::new();
        let mut binding = authenticated_personal_hash_binding(&root);
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建 legacy 请求 handle");
        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        let encoded = STANDARD.encode(b"legacy-native");
        let body = json!({
            "data": json!({
                "peers": [{"id": "100001", "hash": encoded}]
            }).to_string()
        })
        .to_string();
        let receipt = observe_current_personal_hash_response(
            &mut binding,
            &handle,
            FfiSessionOperation::AddressBookRead,
            "https://example.com/api/ab",
            200,
            Some("application/json; charset=utf-8"),
            &body,
        )
        .expect("合法 legacy 响应应被观察")
        .expect("合法 legacy 响应应签发 receipt");
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(binding
            .commit_personal_hash_receipt(&handle, &receipt)
            .expect("模型提交后应激活 native 表"));
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"legacy-native".to_vec())
        );

        let bad_body = json!({
            "data": json!({
                "peers": [
                    {"id": "100002", "hash": STANDARD.encode(b"new")},
                    {"id": "100002", "hash": STANDARD.encode(b"duplicate")}
                ]
            }).to_string()
        })
        .to_string();
        assert!(observe_current_personal_hash_response(
            &mut binding,
            &handle,
            FfiSessionOperation::AddressBookRead,
            "https://example.com/api/ab",
            200,
            Some("application/json"),
            &bad_body,
        )
        .is_err());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        assert!(observe_current_personal_hash_response(
            &mut binding,
            &handle,
            FfiSessionOperation::AddressBookRead,
            "https://example.com/api/ab",
            200,
            Some("text/plain"),
            "null",
        )
        .is_err());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        assert!(observe_current_personal_hash_response(
            &mut binding,
            &handle,
            FfiSessionOperation::AddressBookRead,
            "https://example.com/api/ab",
            200,
            Some("application/json"),
            "NULL",
        )
        .is_err());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
    }

    #[test]
    fn native_commercial_observer_只接受个人_guid_完整分页并在漂移时失效() {
        let root = PersonalHashTestRoot::new();
        let mut binding = authenticated_personal_hash_binding(&root);
        let discovery_handle = binding
            .credentialed_request_handle("https://example.com/api/ab/personal")
            .expect("应创建 commercial discovery handle");
        assert!(observe_current_personal_hash_response(
            &mut binding,
            &discovery_handle,
            FfiSessionOperation::AddressBookCommercial,
            "https://example.com/api/ab/personal",
            200,
            Some("application/json"),
            r#"{"guid":"personal-guid"}"#,
        )
        .expect("应注册商业 personal guid")
        .is_none());

        let page_handle = binding
            .credentialed_request_handle("https://example.com/api/ab/peers")
            .expect("应创建同代新分页 handle");
        assert!(observe_current_personal_hash_response(
            &mut binding,
            &page_handle,
            FfiSessionOperation::AddressBookCommercial,
            "https://example.com/api/ab/peers?current=1&pageSize=100&ab=shared-guid",
            200,
            Some("application/json"),
            &json!({
                "total": 1,
                "data": [{"id": "shared-only", "hash": STANDARD.encode(b"forbidden")}]
            })
            .to_string(),
        )
        .expect("共享地址簿响应应被忽略")
        .is_none());

        let receipt = observe_current_personal_hash_response(
            &mut binding,
            &page_handle,
            FfiSessionOperation::AddressBookCommercial,
            "https://example.com/api/ab/peers?current=1&pageSize=2&ab=personal-guid",
            200,
            Some("application/json"),
            &json!({
                "total": 2,
                "data": [
                    {"id": "100001", "hash": STANDARD.encode(b"commercial-native")},
                    {"id": "100002", "hash": null}
                ]
            })
            .to_string(),
        )
        .expect("完整商业 personal 分页应被观察")
        .expect("完整商业 personal 分页应签发 receipt");
        assert!(binding
            .commit_personal_hash_receipt(&page_handle, &receipt)
            .expect("应提交商业 personal receipt"));
        binding
            .set_address_book_capability(
                &page_handle,
                AddressBookCapability::CommercialMulti,
                false,
            )
            .expect("应确认 commercial 能力");
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"commercial-native".to_vec())
        );

        assert!(observe_current_personal_hash_response(
            &mut binding,
            &page_handle,
            FfiSessionOperation::AddressBookCommercial,
            "https://example.com/api/ab/peers?current=1&pageSize=1&ab=personal-guid",
            200,
            Some("application/json"),
            &json!({
                "total": 2,
                "data": [{"id": "100010", "hash": STANDARD.encode(b"page-one")}]
            })
            .to_string(),
        )
        .expect("第一页应被接受")
        .is_none());
        assert!(observe_current_personal_hash_response(
            &mut binding,
            &page_handle,
            FfiSessionOperation::AddressBookCommercial,
            "https://example.com/api/ab/peers?current=2&pageSize=1&ab=personal-guid",
            200,
            Some("application/json"),
            &json!({
                "total": 3,
                "data": [{"id": "100011", "hash": STANDARD.encode(b"drift")}]
            })
            .to_string(),
        )
        .is_err());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        let invalidated_fence = binding
            .personal_hash_request_fence(&page_handle)
            .expect("应捕获失效后的栅栏");
        assert!(!binding.is_current_commercial_personal_guid(
            &page_handle,
            invalidated_fence,
            "personal-guid"
        ));
    }

    #[test]
    fn 地址簿缓存绑定请求代次并保留_v2_字段() {
        let namespace = "cursor-key";
        let payload = json!({
            "auth_namespace": namespace,
            "ab_entries": [{
                "kind": "issue9_v2",
                "peers": [{
                    "id": "100001",
                    "instance_id": "a".repeat(64),
                    "source": "shared",
                    "permission": "view_only"
                }]
            }]
        })
        .to_string();
        validate_auth_cache_payload(&payload, namespace).expect("应接受同代缓存");
        assert!(validate_auth_cache_payload(&payload, "other-generation").is_err());

        let normalized = normalize_auth_cache_json(payload.as_bytes()).expect("应保留完整缓存");
        let value: Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value["auth_namespace"], namespace);
        assert_eq!(value["ab_entries"][0]["kind"], "issue9_v2");
        assert_eq!(
            value["ab_entries"][0]["peers"][0]["permission"],
            "view_only"
        );

        let forbidden = json!({
            "auth_namespace": namespace,
            "access_token": "secret",
            "ab_entries": []
        })
        .to_string();
        assert!(validate_auth_cache_payload(&forbidden, namespace).is_err());
    }

    #[test]
    fn 旧缓存凭证字段被移除且不丢扩展字段() {
        let legacy = json!({
            "access_token": "legacy-secret",
            "ab_entries": [{"kind": "issue9_v2", "custom": "sentinel"}]
        })
        .to_string();
        let normalized = normalize_auth_cache_json(legacy.as_bytes()).unwrap();
        let value: Value = serde_json::from_str(&normalized).unwrap();
        assert!(value.get("auth_namespace").is_none());
        assert!(value.get("access_token").is_none());
        assert_eq!(value["ab_entries"][0]["custom"], "sentinel");
    }

    #[test]
    fn 登录挑战优先保留服务端_type() {
        let Value::Object(body) = json!({
            "type": "email_check",
            "tfa_type": "email",
            "secret": "challenge-sentinel",
            "user": {
                "name": "alice",
                "verifier": "verifier-must-not-cross-ffi"
            }
        }) else {
            unreachable!();
        };
        let opaque_attempt =
            auth_binding::serialize_auth_attempt(&auth_attempt()).expect("应序列化 attempt");
        let output_json = serialize_login_challenge(&body, 200, &opaque_attempt).unwrap();
        let output: Value = serde_json::from_str(&output_json).unwrap();
        assert_eq!(output["kind"], "challenge");
        assert_eq!(output["challenge_type"], "email_check");
        assert_eq!(output["type"], "email_check");
        assert_eq!(output["tfa_type"], "email");
        assert_eq!(output["native_attempt"], opaque_attempt);
        assert!(!output_json.contains("verifier-must-not-cross-ffi"));
        assert!(output["user"].get("verifier").is_none());
    }

    #[test]
    fn 登录挑战在_type_缺失时回退_tfa_type() {
        let Value::Object(body) = json!({
            "tfa_type": "totp",
            "secret": "challenge-sentinel"
        }) else {
            unreachable!();
        };
        let opaque_attempt =
            auth_binding::serialize_auth_attempt(&auth_attempt()).expect("应序列化 attempt");
        let output: Value =
            serde_json::from_str(&serialize_login_challenge(&body, 200, &opaque_attempt).unwrap())
                .unwrap();
        assert_eq!(output["challenge_type"], "totp");
        assert_eq!(output["type"], "");
        assert_eq!(output["tfa_type"], "totp");
        assert_eq!(output["native_attempt"], opaque_attempt);
    }

    #[test]
    fn 登录请求递归且不区分大小写拒绝_native_保留字段() {
        for value in [
            json!({"native_attempt": "forged"}),
            json!({"nested": {"NaTiVe_Attempt": "forged"}}),
            json!({"items": [{"NATIVE_JOB_ID": "forged"}]}),
        ] {
            assert!(contains_native_reserved_field(&value));
            assert!(validate_and_normalize_login_body(&value.to_string()).is_err());
        }
        let valid = json!({
            "username": "alice",
            "deviceInfo": {"name": "desktop"},
            "items": [1, true, null]
        });
        assert!(!contains_native_reserved_field(&valid));
        let normalized =
            validate_and_normalize_login_body(&format!("  {valid}  ")).expect("合法登录体应规范化");
        assert_eq!(serde_json::from_str::<Value>(&normalized).unwrap(), valid);
        assert!(!normalized.starts_with(' '));
    }

    #[test]
    fn 会话业务白名单拒绝认证端点和错误方法() {
        let base = "https://example.com/rustdesk";
        assert_eq!(
            classify_session_operation(
                StrictHttpMethod::Get,
                "https://example.com/rustdesk/api/ab?page=1",
                base
            )
            .unwrap(),
            FfiSessionOperation::AddressBookRead
        );
        assert_eq!(
            classify_session_operation(
                StrictHttpMethod::Put,
                "https://example.com/rustdesk/api/ab/peer/update/123e4567-e89b",
                base
            )
            .unwrap(),
            FfiSessionOperation::AddressBookCommercial
        );
        assert_eq!(
            commercial_address_book_mutation_guid(
                StrictHttpMethod::Put,
                "https://example.com/rustdesk/api/ab/peer/update/shared-guid",
                base,
            )
            .unwrap()
            .as_deref(),
            Some("shared-guid")
        );
        assert!(commercial_address_book_mutation_guid(
            StrictHttpMethod::Put,
            "https://example.com/rustdesk/api/ab/tag/update/shared-guid",
            base,
        )
        .unwrap()
        .is_none());
        assert!(classify_session_operation(
            StrictHttpMethod::Post,
            "https://example.com/rustdesk/api/login",
            base
        )
        .is_err());
        assert!(classify_session_operation(
            StrictHttpMethod::Get,
            "https://example.com/rustdesk/api/currentUser",
            base
        )
        .is_err());
        assert!(classify_session_operation(
            StrictHttpMethod::Get,
            "https://example.com/rustdesk/api/ab/peer/update/%2e%2e%2flogin",
            base
        )
        .is_err());
        assert!(classify_session_operation(
            StrictHttpMethod::Get,
            "https://example.com/rustdesk/api/audit/conn/active",
            base
        )
        .is_err());
        assert!(classify_session_operation(
            StrictHttpMethod::Put,
            "https://example.com/rustdesk/api/audit",
            base
        )
        .is_err());
    }
}
