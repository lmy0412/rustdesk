use hbb_common::{
    anyhow::{anyhow, bail, Context},
    config::{Config, LocalConfig, Status, APP_NAME},
    ResultType,
};
use librustdesk::{
    common::post_request_sync,
    flutter_ffi,
    hbbs_http::{
        address_book_sync::{AddressBookDelta, SysinfoAddressBookResponse},
        auth_binding::{self, AuthBinding, CredentialedRequestHandle},
        auth_state_store::{AddressBookCapability, AuthAuthorityAnchor},
    },
};
use serde::Serialize as SerializeTrait;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

const ROLE_SEED_LEGACY: &str = "seed-legacy";
const ROLE_SERVICE: &str = "service";
const ROLE_UI_PRODUCER: &str = "ui-event-producer";
const ROLE_INSPECT_STATE: &str = "inspect-state";
const LEGACY_TEST_TOKEN: &str = "issue9-legacy-secret-must-be-scrubbed";
const APP_NAME_PREFIX: &str = "RustDeskIssue9E2E_";
const AUTH_IDENTITY: &[u8] = b"rustdesk-issue9-e2e-main-ui";
const WAIT_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceInput {
    schema: u32,
    api_base: String,
    device_id: String,
    device_uuid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerInput {
    schema: u32,
    api_base: String,
    owner_username: String,
    owner_password: String,
    recipient_username: String,
    recipient_password: String,
    empty_username: String,
    empty_password: String,
    device_id: String,
    device_uuid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseAck {
    schema: u32,
    phase: String,
    expected_cursor: i64,
    target_cursor: i64,
    observed_count: usize,
    device_id: Option<String>,
    instance_id: Option<String>,
    source: Option<String>,
    permission: Option<String>,
}

#[derive(Deserialize)]
struct StrictResponse {
    status: u16,
    content_type: Option<String>,
    body: String,
}

#[derive(Serialize)]
struct ServiceReady {
    schema: u32,
    legacy_scrubbed: bool,
    auth_store_absent: bool,
    ui_event_absent: bool,
    no_credential_request_ok: bool,
}

#[derive(Serialize)]
struct ServiceDone {
    schema: u32,
    legacy_still_empty: bool,
    unrelated_write_persisted: bool,
}

#[derive(Serialize)]
struct ProducerReady {
    schema: u32,
    owner_sysinfo_json: bool,
    recipient_fallback: bool,
    cursor_unchanged: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCredentialedRequest {
    #[serde(flatten)]
    handle: CredentialedRequestHandle,
    cursor: u64,
    capability: AddressBookCapability,
    force_full_pending: bool,
}

#[derive(Serialize)]
struct RefreshEvent<'a> {
    name: &'static str,
    requested_ab_ver: i64,
    target_ab_ver: Option<i64>,
    reset_required: bool,
    session_epoch: u64,
    session_nonce: &'a str,
    source: &'static str,
}

fn main() {
    if let Err(error) = run() {
        let _ = error;
        eprintln!("Issue #9 跨仓客户端角色失败");
        std::process::exit(1);
    }
}

fn run() -> ResultType<()> {
    let (role, root) = parse_args()?;
    let root = absolute_existing_directory(&root)?;
    configure_private_product_config(&root)?;
    match role.as_str() {
        ROLE_SEED_LEGACY => seed_legacy(&root),
        ROLE_SERVICE => run_service(&root),
        ROLE_UI_PRODUCER => run_ui_producer(&root),
        ROLE_INSPECT_STATE => inspect_state(&root),
        _ => bail!("未知的 Issue #9 客户端角色"),
    }
}

fn parse_args() -> ResultType<(String, PathBuf)> {
    let mut role = None;
    let mut root = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--role") if role.is_none() => {
                role = Some(
                    args.next()
                        .and_then(|value| value.into_string().ok())
                        .context("--role 缺少值")?,
                );
            }
            Some("--root") if root.is_none() => {
                root = Some(PathBuf::from(args.next().context("--root 缺少值")?));
            }
            _ => bail!("用法：issue9_process_client --role <角色> --root <私有目录>"),
        }
    }
    Ok((role.context("缺少 --role")?, root.context("缺少 --root")?))
}

fn absolute_existing_directory(path: &Path) -> ResultType<PathBuf> {
    let canonical = fs::canonicalize(path).context("无法解析私有测试目录")?;
    if !canonical.is_dir() {
        bail!("私有测试根不是目录");
    }
    Ok(canonical)
}

fn configure_private_product_config(root: &Path) -> ResultType<()> {
    let config_root = root.join("client-config");
    fs::create_dir_all(&config_root)?;
    set_private_directory_permissions(&config_root)?;
    let fixture_name = root
        .file_name()
        .and_then(|value| value.to_str())
        .context("私有测试根名称无效")?;
    let nonce = fixture_name
        .rsplit('-')
        .next()
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .context("私有测试根缺少随机 nonce")?;
    let app_name = format!("{APP_NAME_PREFIX}{}", &nonce[nonce.len() - 16..]);

    // 只改本测试子进程的非秘密路径变量，不传递任何 token 或密码。
    std::env::set_var("APPDATA", &config_root);
    std::env::set_var("LOCALAPPDATA", &config_root);
    std::env::set_var("XDG_CONFIG_HOME", &config_root);
    *APP_NAME.write().map_err(|_| anyhow!("APP_NAME 锁已损坏"))? = app_name.clone();

    let resolved = Config::path("");
    let resolved = if resolved.exists() {
        fs::canonicalize(&resolved)?
    } else {
        resolved
    };
    #[cfg(windows)]
    {
        if !resolved
            .components()
            .any(|component| component.as_os_str() == app_name.as_str())
        {
            bail!("产品配置未被隔离到专用 Windows 应用目录");
        }
    }
    #[cfg(not(windows))]
    {
        if !resolved.starts_with(&config_root) {
            bail!("产品配置未被隔离到私有测试根");
        }
    }
    Ok(())
}

fn seed_legacy(root: &Path) -> ResultType<()> {
    LocalConfig::set_option("access_token".to_owned(), LEGACY_TEST_TOKEN.to_owned());
    LocalConfig::set_option(
        "user_info".to_owned(),
        r#"{"name":"legacy-issue9"}"#.to_owned(),
    );
    if LocalConfig::get_option("access_token") != LEGACY_TEST_TOKEN {
        bail!("无法预置 legacy access_token");
    }
    write_private_json(&root.join("legacy-seeded.json"), &json!({"schema": 1}))
}

fn run_service(root: &Path) -> ResultType<()> {
    let cached_legacy = LocalConfig::get_option("access_token");
    if cached_legacy != LEGACY_TEST_TOKEN {
        bail!("service 启动前没有读到磁盘预置 legacy access_token");
    }
    auth_binding::scrub_legacy_auth_mirror();
    let legacy_scrubbed = LocalConfig::get_option("access_token").is_empty()
        && LocalConfig::get_option("user_info").is_empty();
    if !legacy_scrubbed {
        bail!("service 未清除 legacy 认证镜像");
    }

    let input: ServiceInput = read_delete_private_json(&root.join("service-input.json"))?;
    if input.schema != 1 {
        bail!("service 输入 schema 无效");
    }
    let sysinfo_url = endpoint(&input.api_base, "api/sysinfo")?;
    let response = post_request_sync(
        sysinfo_url,
        json!({
            "id": input.device_id,
            "uuid": input.device_uuid
        })
        .to_string(),
        "X-Issue9-E2E-Role: service",
    )?;
    let no_credential_request_ok = response == "SYSINFO_UPDATED";
    if !no_credential_request_ok {
        bail!("service 无凭证 sysinfo 契约失败");
    }

    let auth_root = root.join("client-auth");
    let auth_store_absent = !auth_root.exists();
    let ui_event_absent =
        !root.join("accept-event.json").exists() && !root.join("cancel-event.json").exists();
    if !auth_store_absent || !ui_event_absent {
        bail!("service 不得打开 UI auth store 或产生 UI event");
    }
    write_private_json(
        &root.join("service-ready.json"),
        &ServiceReady {
            schema: 1,
            legacy_scrubbed,
            auth_store_absent,
            ui_event_absent,
            no_credential_request_ok,
        },
    )?;

    wait_for_file(root, "service-release")?;
    LocalConfig::set_option("strategy_timestamp".to_owned(), "9001".to_owned());
    Status::set("issue9_service_probe", "complete".to_owned());

    let legacy_still_empty = LocalConfig::get_option("access_token").is_empty()
        && LocalConfig::get_option("user_info").is_empty();
    let unrelated_write_persisted = LocalConfig::get_option("strategy_timestamp") == "9001";
    if !legacy_still_empty || !unrelated_write_persisted {
        bail!("service 后续无关配置写入恢复了 legacy 认证镜像");
    }
    drop(cached_legacy);
    write_private_json(
        &root.join("service-done.json"),
        &ServiceDone {
            schema: 1,
            legacy_still_empty,
            unrelated_write_persisted,
        },
    )
}

fn run_ui_producer(root: &Path) -> ResultType<()> {
    auth_binding::scrub_legacy_auth_mirror();
    let input: ProducerInput = read_delete_private_json(&root.join("producer-input.json"))?;
    if input.schema != 1 {
        bail!("producer 输入 schema 无效");
    }

    let anchor = authority_anchor(root)?;
    auth_binding::initialize_main_ui_auth(anchor)?;
    publish_fixture_api_base(&input.api_base)?;

    login_via_product_ffi(
        &input.api_base,
        &input.owner_username,
        &input.owner_password,
    )?;
    let owner_sysinfo = endpoint(&input.api_base, "api/sysinfo")?;
    let owner_handle = flutter_ffi::main_auth_begin_request(owner_sysinfo.clone())?;
    let owner_response = strict_request(
        &owner_handle,
        owner_sysinfo,
        "POST",
        Some(
            json!({
                "id": input.device_id,
                "uuid": input.device_uuid,
                "hostname": "Issue9 E2E owner host",
                "os": "Windows",
                "ab_ver": 0,
                "address_book_json": true
            })
            .to_string(),
        ),
    )?;
    if owner_response.status != 200 || !is_json(&owner_response.content_type) {
        bail!("owner 合法 identity 未走 sysinfo JSON 路径");
    }
    let owner_json = SysinfoAddressBookResponse::parse(&owner_response.body, 0)?;
    if owner_json.address_book.ab_ver < 1 {
        bail!("owner sysinfo JSON 没有观察到地址簿版本");
    }
    if !flutter_ffi::main_auth_clear_if_current(owner_handle)? {
        bail!("无法在 owner 探测后清除本地会话");
    }

    login_via_product_ffi(
        &input.api_base,
        &input.recipient_username,
        &input.recipient_password,
    )?;
    let (_recipient_handle, initial_delta) =
        fallback_probe(&input.api_base, &input.device_id, &input.device_uuid)?;
    if initial_delta.ab_ver != 0
        || initial_delta.next_ab_ver != 0
        || !initial_delta.changes.is_empty()
    {
        bail!("recipient 在 accept 前不应看到地址簿成员");
    }
    let initial_snapshot: Value = serde_json::from_str(&flutter_ffi::main_auth_snapshot()?)?;
    if initial_snapshot["session"]["cursor"].as_u64() != Some(0) {
        bail!("Rust probe 阶段不得 ACK cursor");
    }
    write_private_json(
        &root.join("producer-ready.json"),
        &ProducerReady {
            schema: 1,
            owner_sysinfo_json: true,
            recipient_fallback: true,
            cursor_unchanged: true,
        },
    )?;

    wait_for_file(root, "accept-go")?;
    let (accept_handle, accept_delta) =
        fallback_probe(&input.api_base, &input.device_id, &input.device_uuid)?;
    let accept_item = accept_delta
        .changes
        .iter()
        .find_map(|change| change.item.as_ref())
        .context("accept delta 缺少 upsert")?;
    if accept_delta.ab_ver != 1
        || accept_delta.next_ab_ver != 1
        || accept_item.source != "shared"
        || accept_item.permission != "view_only"
        || accept_item.instance_id.len() != 64
    {
        bail!("accept delta 的共享语义无效");
    }
    assert_probe_did_not_ack(0)?;
    let accept_session = session_fields(&accept_handle)?;
    write_private_json(
        &root.join("accept-event.json"),
        &RefreshEvent {
            name: "address_book_updated",
            requested_ab_ver: 0,
            target_ab_ver: Some(accept_delta.ab_ver),
            reset_required: accept_delta.reset_required,
            session_epoch: accept_session.0,
            session_nonce: &accept_session.1,
            source: "address_book_probe",
        },
    )?;

    let accept_ack: PhaseAck = wait_read_delete_json(root, "accept-ack.json")?;
    validate_accept_ack(&accept_ack, accept_item)?;
    if !flutter_ffi::main_auth_complete_address_book_pull(
        accept_handle,
        accept_ack.expected_cursor,
        accept_ack.target_cursor,
        false,
    )? {
        bail!("accept ACK 的真实 cursor CAS 失败");
    }
    write_private_json(
        &root.join("accept-producer-acked.json"),
        &json!({"schema": 1}),
    )?;

    wait_for_file(root, "cancel-go")?;
    let (cancel_handle, cancel_delta) =
        fallback_probe(&input.api_base, &input.device_id, &input.device_uuid)?;
    if cancel_delta.ab_ver != 2
        || cancel_delta.next_ab_ver != 2
        || cancel_delta.changes.len() != 1
        || cancel_delta.changes[0].operation != "delete"
        || cancel_delta.changes[0].item.is_some()
    {
        bail!("cancel delta 没有形成精确删除");
    }
    assert_probe_did_not_ack(1)?;
    let cancel_session = session_fields(&cancel_handle)?;
    write_private_json(
        &root.join("cancel-event.json"),
        &RefreshEvent {
            name: "address_book_updated",
            requested_ab_ver: 1,
            target_ab_ver: Some(cancel_delta.ab_ver),
            reset_required: cancel_delta.reset_required,
            session_epoch: cancel_session.0,
            session_nonce: &cancel_session.1,
            source: "address_book_probe",
        },
    )?;

    let cancel_ack: PhaseAck = wait_read_delete_json(root, "cancel-ack.json")?;
    validate_cancel_ack(&cancel_ack)?;
    if !flutter_ffi::main_auth_complete_address_book_pull(
        cancel_handle.clone(),
        cancel_ack.expected_cursor,
        cancel_ack.target_cursor,
        false,
    )? {
        bail!("cancel ACK 的真实 cursor CAS 失败");
    }
    let completed: Value = serde_json::from_str(&flutter_ffi::main_auth_snapshot()?)?;
    if completed["session"]["cursor"].as_u64() != Some(2)
        || completed["session"]["capability"].as_str() != Some("issue9_v2")
        || completed["session"]["force_full_pending"].as_bool() != Some(false)
    {
        bail!("两段 ACK 后的权威认证状态无效");
    }
    if !flutter_ffi::main_auth_clear_if_current(cancel_handle)? {
        bail!("producer 无法清除本地权威会话");
    }

    login_via_product_ffi(
        &input.api_base,
        &input.empty_username,
        &input.empty_password,
    )?;
    let empty_ab_url = endpoint(&input.api_base, "api/ab")?;
    let empty_initial_handle = flutter_ffi::main_auth_begin_request(empty_ab_url.clone())?;
    const FUTURE_CURSOR: i64 = 9_007_199_254_740_991;
    if !flutter_ffi::main_auth_compare_and_set_cursor(
        empty_initial_handle,
        0,
        FUTURE_CURSOR,
        false,
    )? {
        bail!("无法为 future reset 场景预置安全整数 cursor");
    }
    let mut future_url = Url::parse(&empty_ab_url)?;
    future_url
        .query_pairs_mut()
        .append_pair("ab_ver", &FUTURE_CURSOR.to_string())
        .append_pair("page_size", "1");
    let future_handle = flutter_ffi::main_auth_begin_request(future_url.to_string())?;
    let future_response = strict_request(&future_handle, future_url.to_string(), "GET", None)?;
    if future_response.status != 200 || !is_json(&future_response.content_type) {
        bail!("empty 用户 future cursor 请求失败");
    }
    let future_delta = AddressBookDelta::parse(&future_response.body, FUTURE_CURSOR)?;
    if !future_delta.reset_required
        || future_delta.ab_ver != 0
        || future_delta.next_ab_ver != 0
        || !future_delta.changes.is_empty()
    {
        bail!("empty 用户 future cursor 未安全 reset 到 0");
    }
    let trusted_reset_request: FixtureCredentialedRequest =
        serde_json::from_str(&future_handle).context("future reset FFI handle 格式无效")?;
    if trusted_reset_request.cursor != FUTURE_CURSOR as u64
        || trusted_reset_request.capability != AddressBookCapability::Unknown
        || !trusted_reset_request.force_full_pending
        || !auth_binding::authorize_address_book_reset(
            &trusted_reset_request.handle,
            FUTURE_CURSOR as u64,
            future_delta.next_ab_ver as u64,
        )?
    {
        bail!("empty 用户 future reset 未建立当前 worker 可信授权");
    }
    assert_probe_did_not_ack(FUTURE_CURSOR as u64)?;
    if !flutter_ffi::main_auth_complete_address_book_pull(
        future_handle.clone(),
        FUTURE_CURSOR,
        0,
        true,
    )? {
        bail!("empty 用户 future reset ACK0 的真实 cursor CAS 失败");
    }
    let reset_completed: Value = serde_json::from_str(&flutter_ffi::main_auth_snapshot()?)?;
    if reset_completed["session"]["cursor"].as_u64() != Some(0)
        || reset_completed["session"]["capability"].as_str() != Some("issue9_v2")
        || reset_completed["session"]["force_full_pending"].as_bool() != Some(false)
    {
        bail!("empty 用户 future reset ACK0 后权威状态无效");
    }
    if !flutter_ffi::main_auth_clear_if_current(future_handle)? {
        bail!("producer 无法清除 future reset 会话");
    }
    let cleared: Value = serde_json::from_str(&flutter_ffi::main_auth_snapshot()?)?;
    if !cleared["session"].is_null() {
        bail!("producer 清理后仍有认证会话");
    }
    write_private_json(&root.join("producer-done.json"), &json!({"schema": 1}))
}

fn inspect_state(root: &Path) -> ResultType<()> {
    let binding = AuthBinding::open(authority_anchor(root)?)?;
    let snapshot = binding.snapshot();
    if snapshot.corrupt || snapshot.session.is_some() || snapshot.pending_logout_count != 0 {
        bail!("重开 NativeAuthStateV1 后状态不安全");
    }
    verify_private_authority_permissions(binding.authority_directory())?;
    let state_path = binding.authority_directory().join("state.json");
    let state_sha256 = hex::encode(Sha256::digest(fs::read(&state_path)?));
    write_private_json(
        &root.join("state-inspected.json"),
        &json!({
            "schema": 1,
            "checksum_valid": true,
            "session_absent": true,
            "pending_logout_count": snapshot.pending_logout_count,
            "revision": snapshot.revision,
            "auth_epoch": snapshot.auth_epoch,
            "logout_generation": snapshot.logout_generation,
            "state_sha256": state_sha256
        }),
    )
}

fn authority_anchor(root: &Path) -> ResultType<AuthAuthorityAnchor> {
    AuthAuthorityAnchor::from_root_and_identity(root.join("client-auth"), AUTH_IDENTITY)
}

fn publish_fixture_api_base(api_base: &str) -> ResultType<()> {
    let expected = auth_binding::normalize_api_base(api_base)?;
    flutter_ffi::main_stage_and_publish_server_config(
        String::new(),
        String::new(),
        api_base.to_owned(),
        String::new(),
    )?;
    let effective = auth_binding::normalize_api_base(&flutter_ffi::main_get_api_server())?;
    if effective != expected {
        bail!("产品配置入口没有发布 fixture API 地址");
    }
    Ok(())
}

fn login_via_product_ffi(api_base: &str, username: &str, password: &str) -> ResultType<()> {
    let expected_api_base = auth_binding::normalize_api_base(api_base)?;
    let attempt = flutter_ffi::main_auth_begin_login()?;
    let committed = (|| -> ResultType<()> {
        let result = flutter_ffi::main_auth_strict_login_and_commit(
            attempt.clone(),
            json!({
                "username": username,
                "password": password,
                "type": "account",
                "autoLogin": true
            })
            .to_string(),
        )?;
        if result.contains(password)
            || result.contains("\"access_token\"")
            || result.contains("\"authorization\"")
        {
            bail!("产品登录桥返回了禁止暴露的认证材料");
        }
        validate_authenticated_login_dto(&result, &attempt, &expected_api_base)
    })();
    if let Err(error) = committed {
        return fail_before_auth_ack(&attempt, error);
    }

    match flutter_ffi::main_auth_ack_attempt(attempt.clone()) {
        Ok(true) => Ok(()),
        Ok(false) => fail_before_auth_ack(&attempt, anyhow!("登录 ACK 未接纳 exact attempt")),
        Err(error) => fail_before_auth_ack(&attempt, error),
    }
}

fn fail_before_auth_ack<T>(attempt: &str, error: hbb_common::anyhow::Error) -> ResultType<T> {
    match flutter_ffi::main_auth_cancel_attempt(attempt.to_owned()) {
        Ok(true) => Err(error),
        Ok(false) | Err(_) => Err(anyhow!("登录失败且 ACK 前 exact cancel 清理失败")),
    }
}

fn validate_authenticated_login_dto(
    result: &str,
    attempt: &str,
    expected_api_base: &str,
) -> ResultType<()> {
    let Value::Object(value) = serde_json::from_str::<Value>(result)? else {
        bail!("产品登录桥响应不是对象");
    };
    let expected_keys = [
        "capability",
        "cursor",
        "cursor_key",
        "force_full_pending",
        "kind",
        "namespace",
        "native_attempt",
        "normalized_api_base",
        "session_epoch",
        "session_nonce",
        "status",
        "user",
    ];
    if value.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !value.contains_key(*key))
    {
        bail!("产品登录桥 authenticated DTO 字段不完整");
    }
    if value.get("kind").and_then(Value::as_str) != Some("authenticated")
        || value.get("status").and_then(Value::as_u64) != Some(200)
        || value.get("native_attempt").and_then(Value::as_str) != Some(attempt)
        || value.get("normalized_api_base").and_then(Value::as_str) != Some(expected_api_base)
        || !value
            .get("namespace")
            .and_then(Value::as_str)
            .is_some_and(|field| !field.is_empty())
        || !value
            .get("cursor_key")
            .and_then(Value::as_str)
            .is_some_and(|field| !field.is_empty())
        || value.get("session_epoch").and_then(Value::as_u64).is_none()
        || !value
            .get("session_nonce")
            .and_then(Value::as_str)
            .is_some_and(|field| !field.is_empty())
        || value.get("cursor").and_then(Value::as_u64).is_none()
        || value.get("capability").and_then(Value::as_str).is_none()
        || value
            .get("force_full_pending")
            .and_then(Value::as_bool)
            .is_none()
    {
        bail!("产品登录桥 authenticated DTO 代际字段无效");
    }

    let Some(Value::Object(user)) = value.get("user") else {
        bail!("产品登录桥 authenticated DTO 缺少安全用户");
    };
    let expected_user_keys = [
        "avatar",
        "display_name",
        "email",
        "id",
        "is_admin",
        "name",
        "note",
        "status",
    ];
    if user.len() != expected_user_keys.len()
        || expected_user_keys
            .iter()
            .any(|key| !user.contains_key(*key))
        || !user
            .get("id")
            .is_some_and(|field| field.is_null() || field.as_u64().is_some())
        || !user
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|field| !field.is_empty())
        || ["display_name", "avatar", "email", "note"]
            .iter()
            .any(|key| user.get(*key).and_then(Value::as_str).is_none())
        || user.get("status").and_then(Value::as_i64).is_none()
        || user.get("is_admin").and_then(Value::as_bool).is_none()
    {
        bail!("产品登录桥 authenticated DTO 安全用户字段无效");
    }
    Ok(())
}

fn fallback_probe(
    api_base: &str,
    device_id: &str,
    device_uuid: &str,
) -> ResultType<(String, AddressBookDelta)> {
    let sysinfo_url = endpoint(api_base, "api/sysinfo")?;
    let handle = flutter_ffi::main_auth_begin_request(sysinfo_url.clone())?;
    let response = strict_request(
        &handle,
        sysinfo_url,
        "POST",
        Some(
            json!({
                "id": format!("{device_id}-missing"),
                "uuid": device_uuid,
                "ab_ver": cursor_from_handle(&handle)?,
                "address_book_json": true
            })
            .to_string(),
        ),
    )?;
    if response.status != 200 || response.body.trim() != "ID_NOT_FOUND" {
        bail!("不存在 identity 未返回 ID_NOT_FOUND");
    }

    let cursor = cursor_from_handle(&handle)?;
    let mut url = Url::parse(&endpoint(api_base, "api/ab")?)?;
    url.query_pairs_mut()
        .append_pair("ab_ver", &cursor.to_string())
        .append_pair("page_size", "1");
    let response = strict_request(&handle, url.to_string(), "GET", None)?;
    if response.status != 200 || !is_json(&response.content_type) {
        bail!("Bearer /api/ab 回退失败");
    }
    Ok((handle, AddressBookDelta::parse(&response.body, cursor)?))
}

fn strict_request(
    handle: &str,
    url: String,
    method: &str,
    body: Option<String>,
) -> ResultType<StrictResponse> {
    let headers = if body.is_some() {
        json!({
            "Content-Type": "application/json",
            "X-Issue9-E2E-Role": "ui-event-producer"
        })
    } else {
        json!({"X-Issue9-E2E-Role": "ui-event-producer"})
    }
    .to_string();
    let response = flutter_ffi::main_auth_strict_request(
        handle.to_owned(),
        url,
        method.to_owned(),
        body,
        headers,
        10_000,
    )?;
    serde_json::from_str(&response).context("无法解析产品 strict FFI 响应")
}

fn cursor_from_handle(handle: &str) -> ResultType<i64> {
    serde_json::from_str::<Value>(handle)?
        .get("cursor")
        .and_then(Value::as_i64)
        .context("认证请求句柄缺少 cursor")
}

fn session_fields(handle: &str) -> ResultType<(u64, String)> {
    let value: Value = serde_json::from_str(handle)?;
    Ok((
        value["session_epoch"]
            .as_u64()
            .context("认证请求句柄缺少 session_epoch")?,
        value["session_nonce"]
            .as_str()
            .context("认证请求句柄缺少 session_nonce")?
            .to_owned(),
    ))
}

fn assert_probe_did_not_ack(expected: u64) -> ResultType<()> {
    let snapshot: Value = serde_json::from_str(&flutter_ffi::main_auth_snapshot()?)?;
    if snapshot["session"]["cursor"].as_u64() != Some(expected) {
        bail!("Rust probe 阶段意外推进了 cursor");
    }
    Ok(())
}

fn validate_accept_ack(
    ack: &PhaseAck,
    item: &librustdesk::hbbs_http::address_book_sync::AddressBookItem,
) -> ResultType<()> {
    if ack.schema != 1
        || ack.phase != "accept"
        || ack.expected_cursor != 0
        || ack.target_cursor != 1
        || ack.observed_count != 1
        || ack.device_id.as_deref() != Some(item.device_id.as_str())
        || ack.instance_id.as_deref() != Some(item.instance_id.as_str())
        || ack.source.as_deref() != Some("shared")
        || ack.permission.as_deref() != Some("view_only")
    {
        bail!("Flutter accept ACK 未证明共享条目中间态");
    }
    Ok(())
}

fn validate_cancel_ack(ack: &PhaseAck) -> ResultType<()> {
    if ack.schema != 1
        || ack.phase != "cancel"
        || ack.expected_cursor != 1
        || ack.target_cursor != 2
        || ack.observed_count != 0
        || ack.device_id.is_some()
        || ack.instance_id.is_some()
        || ack.source.is_some()
        || ack.permission.is_some()
    {
        bail!("Flutter cancel ACK 未证明共享条目消失中间态");
    }
    Ok(())
}

fn endpoint(base: &str, suffix: &str) -> ResultType<String> {
    let mut url = Url::parse(base)?;
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/{}", suffix.trim_start_matches('/')));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn is_json(content_type: &Option<String>) -> bool {
    content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn wait_for_file(root: &Path, name: &str) -> ResultType<PathBuf> {
    let path = root.join(name);
    let started = Instant::now();
    while !path.is_file() {
        if started.elapsed() >= WAIT_TIMEOUT {
            bail!("等待 barrier 超时：{name}");
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(path)
}

fn wait_read_delete_json<T>(root: &Path, name: &str) -> ResultType<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let path = wait_for_file(root, name)?;
    read_delete_private_json(&path)
}

fn read_delete_private_json<T>(path: &Path) -> ResultType<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let bytes = fs::read(path).with_context(|| format!("无法读取 {}", path.display()))?;
    fs::remove_file(path).with_context(|| format!("无法删除 {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("无法解析 {}", path.display()))
}

fn write_private_json(path: &Path, value: &impl SerializeTrait) -> ResultType<()> {
    let bytes = serde_json::to_vec(value)?;
    let directory = path.parent().context("私有 JSON 路径缺少父目录")?;
    let leaf = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("私有 JSON 文件名无效")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = directory.join(format!(".{leaf}.{}.{nonce}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> ResultType<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn set_private_directory_permissions(path: &Path) -> ResultType<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn verify_private_authority_permissions(directory: &Path) -> ResultType<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(directory)?.permissions().mode() & 0o777 != 0o700 {
            bail!("NativeAuthStateV1 目录权限不是 0700");
        }
        for name in ["state.json", "writer.lock"] {
            let path = directory.join(name);
            if path.exists() && fs::metadata(path)?.permissions().mode() & 0o777 != 0o600 {
                bail!("NativeAuthStateV1 文件权限不是 0600");
            }
        }
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}
