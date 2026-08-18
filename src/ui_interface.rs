#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
use hbb_common::anyhow::{anyhow, Context};
#[cfg(any(target_os = "android", target_os = "ios"))]
use hbb_common::password_security;
use hbb_common::{
    allow_err,
    bytes::Bytes,
    config::{self, keys::*, Config, LocalConfig, PeerConfig, CONNECT_TIMEOUT, RENDEZVOUS_PORT},
    directories_next,
    futures::future::join_all,
    log,
    rendezvous_proto::*,
    tokio, ResultType,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::{
    sleep,
    tokio::{sync::mpsc, time},
};
use serde_derive::{Deserialize, Serialize};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::process::Child;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::common::SOFTWARE_UPDATE_URL;
#[cfg(feature = "flutter")]
use crate::hbbs_http::account;
#[cfg(not(any(target_os = "ios")))]
use crate::ipc;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
use crate::{
    common::{
        strict_http_request_blocking, strict_http_request_no_bearer_blocking, RequestSecurityClass,
        StrictHttpMethod, StrictHttpRequest,
    },
    hbbs_http::auth_binding::{
        self, AuthAttempt, AuthAuthorityAnchor, AuthSafeUser, CredentialedRequestHandle,
        DeviceIdentitySnapshot, PendingLogoutOutcome,
    },
};

type Message = RendezvousMessage;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;

#[derive(Clone, Debug, Serialize)]
pub struct UiStatus {
    pub status_num: i32,
    #[cfg(not(feature = "flutter"))]
    pub key_confirmed: bool,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub mouse_time: i64,
    #[cfg(not(feature = "flutter"))]
    pub id: String,
    #[cfg(feature = "flutter")]
    pub video_conn_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginDeviceInfo {
    pub os: String,
    pub r#type: String,
    pub name: String,
}

lazy_static::lazy_static! {
    static ref UI_STATUS : Arc<Mutex<UiStatus>> = Arc::new(Mutex::new(UiStatus{
        status_num: 0,
        #[cfg(not(feature = "flutter"))]
        key_confirmed: false,
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        mouse_time: 0,
        #[cfg(not(feature = "flutter"))]
        id: "".to_owned(),
        #[cfg(feature = "flutter")]
        video_conn_count: 0,
    }));
    static ref ASYNC_JOB_STATUS : Arc<Mutex<String>> = Default::default();
    static ref ASYNC_HTTP_STATUS : Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref TEMPORARY_PASSWD : Arc<Mutex<String>> = Arc::new(Mutex::new("".to_owned()));
    static ref IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS : Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    static ref SERVER_CONFIG_PUBLISH_LOCK : Mutex<()> = Mutex::new(());
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
#[derive(Clone)]
enum SciterAuthGuard {
    Attempt(AuthAttempt),
    Session(CredentialedRequestHandle),
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
struct SciterAuthJob {
    next_id: u64,
    active_id: u64,
    status: String,
    guard: Option<SciterAuthGuard>,
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
impl Default for SciterAuthJob {
    fn default() -> Self {
        Self {
            next_id: 0,
            active_id: 0,
            status: String::new(),
            guard: None,
        }
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SciterSessionOperation {
    CurrentUser,
    LegacyAddressBookGet,
    LegacyAddressBookUpdate,
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
impl SciterSessionOperation {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "current_user" => Some(Self::CurrentUser),
            "address_book_get" => Some(Self::LegacyAddressBookGet),
            "address_book_update" => Some(Self::LegacyAddressBookUpdate),
            _ => None,
        }
    }

    fn endpoint(self) -> &'static str {
        match self {
            Self::CurrentUser => "api/currentUser",
            Self::LegacyAddressBookGet => "api/ab/get",
            Self::LegacyAddressBookUpdate => "api/ab",
        }
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
const SCITER_AUTH_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
const SCITER_AUTH_MAX_LOGIN_BODY_BYTES: usize = 64 * 1024;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
const SCITER_AUTH_MAX_ATTEMPT_BYTES: usize = 8 * 1024;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
const SCITER_AUTH_MAX_SESSION_BODY_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
const SCITER_AUTH_MAX_SAFE_TEXT_BYTES: usize = 4096;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
lazy_static::lazy_static! {
    static ref SCITER_AUTH_JOB: Arc<Mutex<SciterAuthJob>> =
        Arc::new(Mutex::new(SciterAuthJob::default()));
    static ref SCITER_AUTH_START_MUTEX: Mutex<()> = Mutex::new(());
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref OPTION_SYNCED: Arc<Mutex<bool>> = Default::default();
    static ref OPTIONS : Arc<Mutex<HashMap<String, String>>> = {
        let mut options = Config::get_options();
        remove_protected_options(&mut options);
        Arc::new(Mutex::new(options))
    };
    pub static ref SENDER : Mutex<mpsc::UnboundedSender<ipc::Data>> = Mutex::new(check_connect_status(true));
    static ref CHILDREN : Children = Default::default();
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    pub static ref IS_FILE_TRANSFER_ENABLED: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
}

const INIT_ASYNC_JOB_STATUS: &str = " ";

const AUDIT_CAPABILITY_IPC_POSTFIX: &str = "_audit_capability_v1";
const AUDIT_CAPABILITY_TTL_MS: u64 = 15_000;
const AUDIT_CAPABILITY_MAX_ACTIVE: usize = 256;
const AUDIT_CAPABILITY_MAX_IPC_BYTES: usize = 64 * 1024;
const AUDIT_CAPABILITY_MAX_REMOTE_SESSION_ID_BYTES: usize = 512;
const AUDIT_CAPABILITY_MAX_PEER_ID_BYTES: usize = 512;
const AUDIT_CAPABILITY_MAX_GUID_BYTES: usize = 512;
const AUDIT_CAPABILITY_MAX_NOTE_BYTES: usize = 16 * 1024;

/// 远程会话只能持有不含账号令牌的短时审计能力。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditCapability {
    pub capability_id: String,
    pub session_epoch: u64,
    pub session_nonce: String,
    pub normalized_api_base: String,
    pub remote_session_id: String,
    pub expires_at_unix_ms: u64,
    pub operation: AuditCapabilityKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCapabilityKind {
    ReadGuid,
    WriteNote,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum AuditOperation {
    ReadGuid {
        peer_id: String,
        connection_session_id: u64,
        conn_type: i32,
    },
    WriteNote {
        guid: String,
        peer_id: String,
        connection_session_id: u64,
        note: String,
    },
}

impl AuditOperation {
    fn kind(&self) -> AuditCapabilityKind {
        match self {
            Self::ReadGuid { .. } => AuditCapabilityKind::ReadGuid,
            Self::WriteNote { .. } => AuditCapabilityKind::WriteNote,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum AuditExecutionResult {
    Guid(String),
    NoteWritten,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRemoteSessionTicket {
    launch_nonce: String,
    remote_session_id: String,
}

#[derive(Clone)]
struct AuditCapabilityRecord {
    capability: AuditCapability,
    operation: AuditOperation,
    handle: crate::hbbs_http::auth_binding::CredentialedRequestHandle,
}

#[derive(Default)]
struct AuditCapabilityRegistry {
    active: HashMap<String, AuditCapabilityRecord>,
}

impl AuditCapabilityRegistry {
    fn issue(
        &mut self,
        remote_session_id: String,
        operation: AuditOperation,
        handle: crate::hbbs_http::auth_binding::CredentialedRequestHandle,
        now_unix_ms: u64,
    ) -> hbb_common::ResultType<AuditCapability> {
        self.active.retain(|_, record| {
            record.capability.expires_at_unix_ms > now_unix_ms
                && crate::hbbs_http::auth_binding::is_request_current(&record.handle)
        });
        if self.active.len() >= AUDIT_CAPABILITY_MAX_ACTIVE {
            hbb_common::bail!("当前审计能力数量已达上限");
        }
        let expires_at_unix_ms = now_unix_ms
            .checked_add(AUDIT_CAPABILITY_TTL_MS)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计能力过期时间溢出"))?;
        let capability_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let capability = AuditCapability {
            capability_id: capability_id.clone(),
            session_epoch: handle.session_epoch,
            session_nonce: handle.session_nonce.clone(),
            normalized_api_base: handle.normalized_api_base.clone(),
            remote_session_id,
            expires_at_unix_ms,
            operation: operation.kind(),
        };
        self.active.insert(
            capability_id,
            AuditCapabilityRecord {
                capability: capability.clone(),
                operation,
                handle,
            },
        );
        Ok(capability)
    }

    fn consume(
        &mut self,
        capability: &AuditCapability,
        operation: &AuditOperation,
        now_unix_ms: u64,
    ) -> hbb_common::ResultType<crate::hbbs_http::auth_binding::CredentialedRequestHandle> {
        // 先移除再校验，错误、重复和并发执行都不能复用同一个能力。
        let record = self
            .active
            .remove(&capability.capability_id)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计能力不存在或已被使用"))?;
        if &record.capability != capability
            || &record.operation != operation
            || capability.operation != operation.kind()
        {
            hbb_common::bail!("审计能力与请求不匹配");
        }
        if capability.expires_at_unix_ms <= now_unix_ms {
            hbb_common::bail!("审计能力已过期");
        }
        if capability.session_epoch != record.handle.session_epoch
            || capability.session_nonce != record.handle.session_nonce
            || capability.normalized_api_base != record.handle.normalized_api_base
        {
            hbb_common::bail!("审计能力认证代际不匹配");
        }
        Ok(record.handle)
    }
}

#[derive(Clone)]
struct AuditRemoteBinding {
    remote_session_id: String,
    connection_session_id: u64,
}

#[derive(Clone)]
struct AuditLaunchRecord {
    expected_pid: u32,
    peer_id: String,
    conn_type: i32,
    binding: Option<AuditRemoteBinding>,
}

#[derive(Default)]
struct AuditLaunchRegistry {
    launches: HashMap<String, AuditLaunchRecord>,
}

impl AuditLaunchRegistry {
    fn register_launch(
        &mut self,
        launch_nonce: String,
        expected_pid: u32,
        peer_id: String,
        conn_type: i32,
    ) -> hbb_common::ResultType<()> {
        validate_audit_launch_nonce(&launch_nonce)?;
        validate_audit_text(
            &peer_id,
            "审计对端标识",
            AUDIT_CAPABILITY_MAX_PEER_ID_BYTES,
            false,
            false,
        )?;
        if expected_pid == 0 || !(0..=4).contains(&conn_type) {
            hbb_common::bail!("审计远程进程登记参数无效");
        }
        if self.launches.len() >= AUDIT_CAPABILITY_MAX_ACTIVE
            && !self.launches.contains_key(&launch_nonce)
        {
            hbb_common::bail!("审计远程进程登记数量已达上限");
        }
        match self.launches.get(&launch_nonce) {
            Some(existing)
                if existing.expected_pid != expected_pid
                    || existing.peer_id != peer_id
                    || existing.conn_type != conn_type =>
            {
                hbb_common::bail!("审计启动随机数已绑定其他远程进程");
            }
            Some(_) => return Ok(()),
            None => {}
        }
        self.launches.insert(
            launch_nonce,
            AuditLaunchRecord {
                expected_pid,
                peer_id,
                conn_type,
                binding: None,
            },
        );
        Ok(())
    }

    fn bind_verified_process(
        &mut self,
        launch_nonce: &str,
        actual_pid: u32,
        connection_session_id: u64,
    ) -> hbb_common::ResultType<AuditRemoteSessionTicket> {
        validate_audit_launch_nonce(launch_nonce)?;
        if actual_pid == 0 || connection_session_id == 0 {
            hbb_common::bail!("审计远程会话登记参数无效");
        }
        let record = self
            .launches
            .get_mut(launch_nonce)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计远程进程未由主界面启动"))?;
        if record.expected_pid != actual_pid {
            hbb_common::bail!("审计远程进程身份不匹配");
        }
        if record.binding.as_ref().map_or(true, |binding| {
            binding.connection_session_id != connection_session_id
        }) {
            record.binding = Some(AuditRemoteBinding {
                remote_session_id: hbb_common::uuid::Uuid::new_v4().to_string(),
                connection_session_id,
            });
        }
        let binding = record
            .binding
            .as_ref()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计远程会话登记失败"))?;
        Ok(AuditRemoteSessionTicket {
            launch_nonce: launch_nonce.to_owned(),
            remote_session_id: binding.remote_session_id.clone(),
        })
    }

    fn operation_for_verified_process(
        &self,
        ticket: &AuditRemoteSessionTicket,
        actual_pid: u32,
        request: &AuditOperationRequest,
    ) -> hbb_common::ResultType<(String, AuditOperation)> {
        validate_audit_launch_nonce(&ticket.launch_nonce)?;
        validate_audit_remote_session_id(&ticket.remote_session_id)?;
        let record = self
            .launches
            .get(&ticket.launch_nonce)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计远程进程登记不存在"))?;
        if actual_pid == 0 || record.expected_pid != actual_pid {
            hbb_common::bail!("审计远程进程身份不匹配");
        }
        let binding = record
            .binding
            .as_ref()
            .filter(|binding| binding.remote_session_id == ticket.remote_session_id)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("审计远程会话登记已失效"))?;
        let operation = match request {
            AuditOperationRequest::ReadGuid => AuditOperation::ReadGuid {
                peer_id: record.peer_id.clone(),
                connection_session_id: binding.connection_session_id,
                conn_type: record.conn_type,
            },
            AuditOperationRequest::WriteNote { guid, note } => AuditOperation::WriteNote {
                guid: guid.clone(),
                peer_id: record.peer_id.clone(),
                connection_session_id: binding.connection_session_id,
                note: note.clone(),
            },
        };
        validate_audit_operation(&operation)?;
        Ok((binding.remote_session_id.clone(), operation))
    }

    #[cfg(any(
        test,
        not(any(target_os = "android", target_os = "ios", feature = "flutter"))
    ))]
    fn remove_pid(&mut self, pid: u32) {
        self.launches.retain(|_, record| record.expected_pid != pid);
    }

    fn remote_session_is_current(&self, remote_session_id: &str) -> bool {
        self.launches.values().any(|record| {
            record
                .binding
                .as_ref()
                .is_some_and(|binding| binding.remote_session_id == remote_session_id)
        })
    }
}

lazy_static::lazy_static! {
    static ref AUDIT_CAPABILITIES: Arc<Mutex<AuditCapabilityRegistry>> =
        Arc::new(Mutex::new(AuditCapabilityRegistry::default()));
    static ref AUDIT_LAUNCHES: Arc<Mutex<AuditLaunchRegistry>> =
        Arc::new(Mutex::new(AuditLaunchRegistry::default()));
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum AuditOperationRequest {
    ReadGuid,
    WriteNote { guid: String, note: String },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
enum AuditIpcRequest {
    Register {
        launch_nonce: String,
        connection_session_id: u64,
    },
    Issue {
        ticket: AuditRemoteSessionTicket,
        operation: AuditOperationRequest,
    },
    Execute {
        capability: AuditCapability,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "response", rename_all = "snake_case")]
enum AuditIpcResponse {
    Registered {
        ticket: AuditRemoteSessionTicket,
        available: bool,
    },
    Issued {
        capability: AuditCapability,
    },
    Completed {
        result: AuditExecutionResult,
    },
    Error {
        message: String,
    },
}

fn audit_unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn validate_audit_text(
    value: &str,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
    allow_line_breaks: bool,
) -> hbb_common::ResultType<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character.is_control()
                && !(allow_line_breaks && matches!(character, '\r' | '\n' | '\t'))
        })
    {
        hbb_common::bail!("{field}无效");
    }
    Ok(())
}

fn validate_audit_remote_session_id(remote_session_id: &str) -> hbb_common::ResultType<()> {
    validate_audit_text(
        remote_session_id,
        "远程会话标识",
        AUDIT_CAPABILITY_MAX_REMOTE_SESSION_ID_BYTES,
        false,
        false,
    )
}

fn validate_audit_launch_nonce(launch_nonce: &str) -> hbb_common::ResultType<()> {
    validate_audit_text(launch_nonce, "审计启动随机数", 64, false, false)?;
    hbb_common::uuid::Uuid::parse_str(launch_nonce)
        .map_err(|_| hbb_common::anyhow::anyhow!("审计启动随机数格式无效"))?;
    Ok(())
}

fn validate_audit_operation(operation: &AuditOperation) -> hbb_common::ResultType<()> {
    match operation {
        AuditOperation::ReadGuid {
            peer_id,
            connection_session_id,
            conn_type,
        } => {
            validate_audit_text(
                peer_id,
                "审计对端标识",
                AUDIT_CAPABILITY_MAX_PEER_ID_BYTES,
                false,
                false,
            )?;
            if *connection_session_id == 0 || !(0..=4).contains(conn_type) {
                hbb_common::bail!("审计连接参数无效");
            }
        }
        AuditOperation::WriteNote {
            guid,
            peer_id,
            connection_session_id,
            note,
        } => {
            validate_audit_text(
                guid,
                "审计GUID",
                AUDIT_CAPABILITY_MAX_GUID_BYTES,
                true,
                false,
            )?;
            validate_audit_text(
                peer_id,
                "审计对端标识",
                AUDIT_CAPABILITY_MAX_PEER_ID_BYTES,
                guid.is_empty(),
                false,
            )?;
            if guid.is_empty() && *connection_session_id == 0 {
                hbb_common::bail!("审计连接参数无效");
            }
            validate_audit_text(
                note,
                "审计备注",
                AUDIT_CAPABILITY_MAX_NOTE_BYTES,
                true,
                true,
            )?;
        }
    }
    Ok(())
}

fn audit_endpoint(
    normalized_api_base: &str,
    operation: &AuditOperation,
) -> hbb_common::ResultType<String> {
    let mut url = url::Url::parse(normalized_api_base)
        .map_err(|_| hbb_common::anyhow::anyhow!("权威API地址无效"))?;
    let base_path = url.path().trim_end_matches('/');
    match operation {
        AuditOperation::ReadGuid {
            peer_id,
            connection_session_id,
            conn_type,
        } => {
            url.set_path(&format!("{base_path}/api/audit/conn/active"));
            url.query_pairs_mut()
                .clear()
                .append_pair("id", peer_id)
                .append_pair("session_id", &connection_session_id.to_string())
                .append_pair("conn_type", &conn_type.to_string());
        }
        AuditOperation::WriteNote { .. } => {
            url.set_path(&format!("{base_path}/api/audit"));
            url.set_query(None);
        }
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

fn current_audit_session(
    remote_session_id: &str,
) -> hbb_common::ResultType<crate::hbbs_http::auth_binding::AuthSessionSnapshot> {
    validate_audit_remote_session_id(remote_session_id)?;
    let session = crate::hbbs_http::auth_binding::auth_snapshot()?
        .session
        .ok_or_else(|| hbb_common::anyhow::anyhow!("当前没有有效认证会话"))?;
    let effective_api_base = crate::hbbs_http::auth_binding::normalize_api_base(&get_api_server())?;
    if session.normalized_api_base != effective_api_base {
        hbb_common::bail!("当前认证会话与有效API地址不匹配");
    }
    Ok(session)
}

fn audit_capability_available(remote_session_id: &str) -> bool {
    current_audit_session(remote_session_id).is_ok()
}

fn issue_audit_capability(
    remote_session_id: String,
    operation: AuditOperation,
) -> hbb_common::ResultType<AuditCapability> {
    validate_audit_operation(&operation)?;
    let session = current_audit_session(&remote_session_id)?;
    let target = audit_endpoint(&session.normalized_api_base, &operation)?;
    let handle = crate::hbbs_http::auth_binding::credentialed_request_handle(&target)?;
    AUDIT_CAPABILITIES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计能力状态锁已损坏"))?
        .issue(remote_session_id, operation, handle, audit_unix_time_ms())
}

fn audit_generation_matches_current_session(
    capability: &AuditCapability,
    handle: &crate::hbbs_http::auth_binding::CredentialedRequestHandle,
    session_epoch: u64,
    session_nonce: &str,
    normalized_api_base: &str,
    handle_is_current: bool,
) -> bool {
    capability.session_epoch == session_epoch
        && capability.session_nonce == session_nonce
        && capability.normalized_api_base == normalized_api_base
        && capability.session_epoch == handle.session_epoch
        && capability.session_nonce == handle.session_nonce
        && capability.normalized_api_base == handle.normalized_api_base
        && handle_is_current
}

async fn execute_audit_capability(
    capability: AuditCapability,
    operation: AuditOperation,
) -> hbb_common::ResultType<AuditExecutionResult> {
    validate_audit_operation(&operation)?;
    validate_audit_remote_session_id(&capability.remote_session_id)?;
    let handle = AUDIT_CAPABILITIES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计能力状态锁已损坏"))?
        .consume(&capability, &operation, audit_unix_time_ms())?;
    if !AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .remote_session_is_current(&capability.remote_session_id)
    {
        hbb_common::bail!("审计远程会话登记已失效");
    }

    let session = current_audit_session(&capability.remote_session_id)?;
    if !audit_generation_matches_current_session(
        &capability,
        &handle,
        session.session_epoch,
        &session.session_nonce,
        &session.normalized_api_base,
        crate::hbbs_http::auth_binding::is_request_current(&handle),
    ) {
        hbb_common::bail!("审计能力已随认证会话失效");
    }

    let target = audit_endpoint(&capability.normalized_api_base, &operation)?;
    let request = match &operation {
        AuditOperation::ReadGuid { .. } => {
            crate::common::StrictHttpRequest::new(crate::common::StrictHttpMethod::Get, target)
        }
        AuditOperation::WriteNote {
            guid,
            peer_id,
            connection_session_id,
            note,
        } => {
            let body = if guid.is_empty() {
                serde_json::json!({
                    "id": peer_id,
                    "session_id": connection_session_id,
                    "note": note,
                })
            } else {
                serde_json::json!({
                    "guid": guid,
                    "note": note,
                })
            };
            crate::common::StrictHttpRequest::new(crate::common::StrictHttpMethod::Put, target)
                .json_body(body.to_string())
        }
    };
    let response = crate::common::strict_http_request(&handle, request).await?;
    if response.status == 401 {
        let _ = crate::hbbs_http::auth_binding::clear_auth_session_if_current(&handle);
        hbb_common::bail!("审计请求认证已失效");
    }
    if !response.is_success() {
        hbb_common::bail!("审计请求被服务器拒绝，状态码{}", response.status);
    }
    match operation {
        AuditOperation::ReadGuid { .. } => {
            let mime = response
                .content_type
                .as_deref()
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            if !mime.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
                hbb_common::bail!("审计GUID响应类型无效");
            }
            let guid: String = serde_json::from_str(&response.body)
                .map_err(|_| hbb_common::anyhow::anyhow!("审计GUID响应格式无效"))?;
            validate_audit_text(
                &guid,
                "审计GUID",
                AUDIT_CAPABILITY_MAX_GUID_BYTES,
                false,
                false,
            )?;
            Ok(AuditExecutionResult::Guid(guid))
        }
        AuditOperation::WriteNote { .. } => Ok(AuditExecutionResult::NoteWritten),
    }
}

fn serialize_audit_ipc<T: serde::Serialize>(value: &T) -> hbb_common::ResultType<Bytes> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > AUDIT_CAPABILITY_MAX_IPC_BYTES {
        hbb_common::bail!("审计IPC消息大小无效");
    }
    Ok(Bytes::from(bytes))
}

fn deserialize_audit_ipc<T: for<'de> serde::Deserialize<'de>>(
    bytes: &[u8],
) -> hbb_common::ResultType<T> {
    if bytes.is_empty() || bytes.len() > AUDIT_CAPABILITY_MAX_IPC_BYTES {
        hbb_common::bail!("审计IPC消息大小无效");
    }
    serde_json::from_slice(bytes).map_err(|_| hbb_common::anyhow::anyhow!("审计IPC消息格式无效"))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn send_audit_ipc_response(
    connection: &mut crate::ipc::Connection,
    response: &AuditIpcResponse,
) -> hbb_common::ResultType<()> {
    connection.send_raw(serialize_audit_ipc(response)?).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn handle_audit_ipc_connection(
    stream: parity_tokio_ipc::Connection,
) -> hbb_common::ResultType<()> {
    let mut connection =
        crate::ipc::Connection::new_with_max_packet_length(stream, AUDIT_CAPABILITY_MAX_IPC_BYTES);
    let peer_pid = connection
        .peer_pid()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("无法确认审计IPC对端进程"))?;
    crate::ipc::ensure_peer_executable_matches_current_by_pid_opt(
        Some(peer_pid),
        AUDIT_CAPABILITY_IPC_POSTFIX,
    )?;
    let first = hbb_common::timeout(1_000, connection.next_raw()).await??;
    let request: AuditIpcRequest = deserialize_audit_ipc(&first)?;
    let AuditIpcRequest::Register {
        launch_nonce,
        connection_session_id,
    } = request
    else {
        hbb_common::bail!("审计IPC必须先登记主界面启动的远程进程");
    };
    let ticket = AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .bind_verified_process(&launch_nonce, peer_pid, connection_session_id)?;
    let available = audit_capability_available(&ticket.remote_session_id);
    send_audit_ipc_response(
        &mut connection,
        &AuditIpcResponse::Registered {
            ticket: ticket.clone(),
            available,
        },
    )
    .await?;

    // 可用性探测在登记后即可关闭；只有同一已验证连接继续签发才可能触发网络。
    let issue =
        match tokio::time::timeout(Duration::from_millis(1_000), connection.next_raw()).await {
            Ok(Ok(issue)) => issue,
            _ => return Ok(()),
        };
    let issue: AuditIpcRequest = deserialize_audit_ipc(&issue)?;
    let AuditIpcRequest::Issue {
        ticket: returned_ticket,
        operation: operation_request,
    } = issue
    else {
        hbb_common::bail!("审计IPC签发顺序无效");
    };
    if returned_ticket != ticket {
        hbb_common::bail!("审计远程会话票据不匹配");
    }
    let (remote_session_id, operation) = AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .operation_for_verified_process(&ticket, peer_pid, &operation_request)?;
    let capability = match issue_audit_capability(remote_session_id, operation.clone()) {
        Ok(capability) => capability,
        Err(_) => {
            return send_audit_ipc_response(
                &mut connection,
                &AuditIpcResponse::Error {
                    message: "审计功能当前不可用".to_owned(),
                },
            )
            .await;
        }
    };
    send_audit_ipc_response(
        &mut connection,
        &AuditIpcResponse::Issued {
            capability: capability.clone(),
        },
    )
    .await?;

    // 能力只允许在签发它的这条已验证连接上执行一次。
    let execute = hbb_common::timeout(AUDIT_CAPABILITY_TTL_MS, connection.next_raw()).await??;
    let execute: AuditIpcRequest = deserialize_audit_ipc(&execute)?;
    let AuditIpcRequest::Execute {
        capability: returned_capability,
    } = execute
    else {
        hbb_common::bail!("审计IPC执行顺序无效");
    };
    if returned_capability != capability {
        // 使用错误参数也要消耗刚签发的能力。
        let _ = AUDIT_CAPABILITIES
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("审计能力状态锁已损坏"))?
            .consume(&capability, &operation, audit_unix_time_ms());
        hbb_common::bail!("审计IPC能力不匹配");
    }
    match execute_audit_capability(returned_capability, operation).await {
        Ok(result) => {
            send_audit_ipc_response(&mut connection, &AuditIpcResponse::Completed { result }).await
        }
        Err(_) => {
            send_audit_ipc_response(
                &mut connection,
                &AuditIpcResponse::Error {
                    message: "审计操作失败或授权已失效".to_owned(),
                },
            )
            .await
        }
    }
}

/// 主界面专用审计IPC；重复初始化不创建第二个监听器。
pub fn ensure_audit_capability_ipc_server_started() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        use std::sync::Once;
        static START: Once = Once::new();
        START.call_once(|| {
            std::thread::spawn(|| {
                if let Err(error) = run_audit_capability_ipc_server() {
                    log::error!("审计能力IPC监听器启动失败: {error}");
                }
            });
        });
    }
}

pub fn new_audit_launch_nonce() -> String {
    hbb_common::uuid::Uuid::new_v4().to_string()
}

/// Flutter 同进程会话只能用 native Session 中的真实 peer/连接类型登记。
pub fn register_trusted_in_process_audit_launch(
    launch_nonce: String,
    peer_id: String,
    conn_type: i32,
) -> hbb_common::ResultType<()> {
    AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .register_launch(launch_nonce, std::process::id(), peer_id, conn_type)
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
fn register_spawned_audit_launch(
    launch_nonce: String,
    expected_pid: u32,
    peer_id: String,
    conn_type: i32,
) -> hbb_common::ResultType<()> {
    AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .register_launch(launch_nonce, expected_pid, peer_id, conn_type)
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
fn unregister_spawned_audit_launch(expected_pid: u32) {
    if let Ok(mut launches) = AUDIT_LAUNCHES.lock() {
        launches.remove_pid(expected_pid);
    }
    if let Ok(mut capabilities) = AUDIT_CAPABILITIES.lock() {
        capabilities.active.retain(|_, capability| {
            AUDIT_LAUNCHES
                .lock()
                .map(|launches| {
                    launches.remote_session_is_current(&capability.capability.remote_session_id)
                })
                .unwrap_or(false)
        });
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn run_audit_capability_ipc_server() -> hbb_common::ResultType<()> {
    let mut incoming = crate::ipc::new_listener(AUDIT_CAPABILITY_IPC_POSTFIX).await?;
    while let Some(result) = incoming.next().await {
        match result {
            Ok(stream) => {
                tokio::spawn(async move {
                    if let Err(error) = handle_audit_ipc_connection(stream).await {
                        log::warn!("审计能力IPC请求已安全拒绝: {error}");
                    }
                });
            }
            Err(error) => log::warn!("审计能力IPC连接失败: {error}"),
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn audit_ipc_round_trip(
    launch_nonce: String,
    connection_session_id: u64,
    operation_request: AuditOperationRequest,
) -> hbb_common::ResultType<AuditExecutionResult> {
    let mut connection = crate::ipc::connect(1_000, AUDIT_CAPABILITY_IPC_POSTFIX).await?;
    connection.set_max_packet_length(AUDIT_CAPABILITY_MAX_IPC_BYTES);
    connection
        .send_raw(serialize_audit_ipc(&AuditIpcRequest::Register {
            launch_nonce,
            connection_session_id,
        })?)
        .await?;
    let response = hbb_common::timeout(1_000, connection.next_raw()).await??;
    let response: AuditIpcResponse = deserialize_audit_ipc(&response)?;
    let AuditIpcResponse::Registered {
        ticket,
        available: true,
    } = response
    else {
        hbb_common::bail!("主界面未确认审计远程会话");
    };
    connection
        .send_raw(serialize_audit_ipc(&AuditIpcRequest::Issue {
            ticket,
            operation: operation_request.clone(),
        })?)
        .await?;
    let response = hbb_common::timeout(1_000, connection.next_raw()).await??;
    let response: AuditIpcResponse = deserialize_audit_ipc(&response)?;
    let AuditIpcResponse::Issued { capability } = response else {
        hbb_common::bail!("主界面未签发审计能力");
    };
    if capability.operation
        != match operation_request {
            AuditOperationRequest::ReadGuid => AuditCapabilityKind::ReadGuid,
            AuditOperationRequest::WriteNote { .. } => AuditCapabilityKind::WriteNote,
        }
    {
        hbb_common::bail!("主界面签发了错误类型的审计能力");
    }
    connection
        .send_raw(serialize_audit_ipc(&AuditIpcRequest::Execute {
            capability,
        })?)
        .await?;
    let response = hbb_common::timeout(AUDIT_CAPABILITY_TTL_MS, connection.next_raw()).await??;
    match deserialize_audit_ipc::<AuditIpcResponse>(&response)? {
        AuditIpcResponse::Completed { result } => Ok(result),
        AuditIpcResponse::Error { message } => hbb_common::bail!("{message}"),
        _ => hbb_common::bail!("主界面返回了无效的审计IPC响应"),
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
async fn audit_ipc_round_trip(
    launch_nonce: String,
    connection_session_id: u64,
    operation_request: AuditOperationRequest,
) -> hbb_common::ResultType<AuditExecutionResult> {
    // 移动端主界面与远程会话同进程，仍使用同一套签发、一次性消费和代际校验。
    let pid = std::process::id();
    let ticket = AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .bind_verified_process(&launch_nonce, pid, connection_session_id)?;
    let (remote_session_id, operation) = AUDIT_LAUNCHES
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("审计远程会话登记锁已损坏"))?
        .operation_for_verified_process(&ticket, pid, &operation_request)?;
    let capability = issue_audit_capability(remote_session_id, operation.clone())?;
    execute_audit_capability(capability, operation).await
}

pub async fn read_audit_guid_via_main_ui(
    launch_nonce: String,
    connection_session_id: u64,
) -> hbb_common::ResultType<String> {
    match audit_ipc_round_trip(
        launch_nonce,
        connection_session_id,
        AuditOperationRequest::ReadGuid,
    )
    .await?
    {
        AuditExecutionResult::Guid(guid) => Ok(guid),
        AuditExecutionResult::NoteWritten => {
            hbb_common::bail!("主界面返回了错误类型的审计结果")
        }
    }
}

pub async fn write_audit_note_via_main_ui(
    launch_nonce: String,
    connection_session_id: u64,
    guid: String,
    note: String,
) -> hbb_common::ResultType<()> {
    match audit_ipc_round_trip(
        launch_nonce,
        connection_session_id,
        AuditOperationRequest::WriteNote { guid, note },
    )
    .await?
    {
        AuditExecutionResult::NoteWritten => Ok(()),
        AuditExecutionResult::Guid(_) => {
            hbb_common::bail!("主界面返回了错误类型的审计结果")
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn audit_capability_available_over_ipc(
    launch_nonce: String,
    connection_session_id: u64,
) -> bool {
    let Ok(mut connection) = crate::ipc::connect(1_000, AUDIT_CAPABILITY_IPC_POSTFIX).await else {
        return false;
    };
    connection.set_max_packet_length(AUDIT_CAPABILITY_MAX_IPC_BYTES);
    let Ok(request) = serialize_audit_ipc(&AuditIpcRequest::Register {
        launch_nonce,
        connection_session_id,
    }) else {
        return false;
    };
    if connection.send_raw(request).await.is_err() {
        return false;
    }
    let Ok(Ok(response)) = hbb_common::timeout(1_000, connection.next_raw()).await else {
        return false;
    };
    matches!(
        deserialize_audit_ipc::<AuditIpcResponse>(&response),
        Ok(AuditIpcResponse::Registered {
            available: true,
            ..
        })
    )
}

#[cfg(any(target_os = "android", target_os = "ios"))]
async fn audit_capability_available_over_ipc(
    launch_nonce: String,
    connection_session_id: u64,
) -> bool {
    let Ok(ticket) = AUDIT_LAUNCHES
        .lock()
        .map_err(|_| ())
        .and_then(|mut launches| {
            launches
                .bind_verified_process(&launch_nonce, std::process::id(), connection_session_id)
                .map_err(|_| ())
        })
    else {
        return false;
    };
    audit_capability_available(&ticket.remote_session_id)
}

#[tokio::main(flavor = "current_thread")]
pub async fn audit_capability_available_blocking(
    launch_nonce: String,
    connection_session_id: u64,
) -> bool {
    audit_capability_available_over_ipc(launch_nonce, connection_session_id).await
}

#[tokio::main(flavor = "current_thread")]
pub async fn write_audit_note_via_main_ui_blocking(
    launch_nonce: String,
    connection_session_id: u64,
    guid: String,
    note: String,
) -> hbb_common::ResultType<()> {
    write_audit_note_via_main_ui(launch_nonce, connection_session_id, guid, note).await
}

#[cfg(test)]
mod issue9_audit_capability_tests {
    use super::*;
    use hbb_common::bytes::BytesMut;
    use hbb_common::tokio_util::codec::Decoder;
    use std::cell::Cell;

    fn launch_nonce() -> String {
        "11111111-2222-4333-8444-555555555555".to_owned()
    }

    fn synthetic_handle() -> crate::hbbs_http::auth_binding::CredentialedRequestHandle {
        crate::hbbs_http::auth_binding::CredentialedRequestHandle {
            request_context_id: "request-context".to_owned(),
            normalized_api_base: "https://api.example.test".to_owned(),
            namespace: "namespace".to_owned(),
            session_epoch: 7,
            session_nonce: "session-nonce".to_owned(),
            cursor_key: "cursor-key".to_owned(),
        }
    }

    #[test]
    fn audit_launch_registry_rejects_forged_pid_and_nonce_before_execution() {
        let mut launches = AuditLaunchRegistry::default();
        launches
            .register_launch(launch_nonce(), 41, "trusted-peer".to_owned(), 0)
            .unwrap();
        let executions = Cell::new(0usize);

        let forged_pid = launches
            .bind_verified_process(&launch_nonce(), 42, 91)
            .and_then(|ticket| {
                launches.operation_for_verified_process(
                    &ticket,
                    42,
                    &AuditOperationRequest::ReadGuid,
                )
            });
        if forged_pid.is_ok() {
            executions.set(executions.get() + 1);
        }
        assert!(forged_pid.is_err());

        let forged_nonce = launches
            .bind_verified_process("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", 41, 91)
            .and_then(|ticket| {
                launches.operation_for_verified_process(
                    &ticket,
                    41,
                    &AuditOperationRequest::ReadGuid,
                )
            });
        if forged_nonce.is_ok() {
            executions.set(executions.get() + 1);
        }
        assert!(forged_nonce.is_err());
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn audit_issue_uses_registered_peer_connection_and_type_only() {
        let mut launches = AuditLaunchRegistry::default();
        launches
            .register_launch(launch_nonce(), 77, "registered-peer".to_owned(), 3)
            .unwrap();
        let ticket = launches
            .bind_verified_process(&launch_nonce(), 77, 1234)
            .unwrap();
        let (_, operation) = launches
            .operation_for_verified_process(&ticket, 77, &AuditOperationRequest::ReadGuid)
            .unwrap();
        assert_eq!(
            operation,
            AuditOperation::ReadGuid {
                peer_id: "registered-peer".to_owned(),
                connection_session_id: 1234,
                conn_type: 3,
            }
        );
    }

    #[test]
    fn audit_reconnect_and_process_exit_invalidate_old_remote_ticket() {
        let mut launches = AuditLaunchRegistry::default();
        launches
            .register_launch(launch_nonce(), 77, "registered-peer".to_owned(), 0)
            .unwrap();
        let old_ticket = launches
            .bind_verified_process(&launch_nonce(), 77, 10)
            .unwrap();
        let new_ticket = launches
            .bind_verified_process(&launch_nonce(), 77, 11)
            .unwrap();
        assert_ne!(old_ticket.remote_session_id, new_ticket.remote_session_id);
        assert!(launches
            .operation_for_verified_process(&old_ticket, 77, &AuditOperationRequest::ReadGuid,)
            .is_err());
        launches.remove_pid(77);
        assert!(launches
            .operation_for_verified_process(&new_ticket, 77, &AuditOperationRequest::ReadGuid,)
            .is_err());
    }

    #[test]
    fn audit_capability_is_one_shot_and_mismatch_is_consumed() {
        let operation = AuditOperation::ReadGuid {
            peer_id: "peer".to_owned(),
            connection_session_id: 9,
            conn_type: 0,
        };
        let mut registry = AuditCapabilityRegistry::default();
        let capability = registry
            .issue(
                "remote-session".to_owned(),
                operation.clone(),
                synthetic_handle(),
                100,
            )
            .unwrap();
        let mut forged = capability.clone();
        forged.remote_session_id = "other-session".to_owned();
        assert!(registry.consume(&forged, &operation, 101).is_err());
        assert!(registry.consume(&capability, &operation, 101).is_err());
    }

    #[test]
    fn expired_audit_capability_fails_before_execution() {
        let operation = AuditOperation::WriteNote {
            guid: "guid".to_owned(),
            peer_id: "peer".to_owned(),
            connection_session_id: 9,
            note: "note".to_owned(),
        };
        let mut registry = AuditCapabilityRegistry::default();
        let capability = registry
            .issue(
                "remote-session".to_owned(),
                operation.clone(),
                synthetic_handle(),
                100,
            )
            .unwrap();
        let executions = Cell::new(0usize);
        if registry
            .consume(&capability, &operation, 100 + AUDIT_CAPABILITY_TTL_MS)
            .is_ok()
        {
            executions.set(executions.get() + 1);
        }
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn logout_generation_and_base_change_fail_before_execution() {
        let operation = AuditOperation::ReadGuid {
            peer_id: "peer".to_owned(),
            connection_session_id: 9,
            conn_type: 0,
        };
        let mut registry = AuditCapabilityRegistry::default();
        let handle = synthetic_handle();
        let capability = registry
            .issue("remote-session".to_owned(), operation, handle.clone(), 100)
            .unwrap();
        let executions = Cell::new(0usize);
        for matches in [
            audit_generation_matches_current_session(
                &capability,
                &handle,
                8,
                &handle.session_nonce,
                &handle.normalized_api_base,
                true,
            ),
            audit_generation_matches_current_session(
                &capability,
                &handle,
                handle.session_epoch,
                "new-session-nonce",
                &handle.normalized_api_base,
                true,
            ),
            audit_generation_matches_current_session(
                &capability,
                &handle,
                handle.session_epoch,
                &handle.session_nonce,
                "https://other.example.test",
                true,
            ),
            audit_generation_matches_current_session(
                &capability,
                &handle,
                handle.session_epoch,
                &handle.session_nonce,
                &handle.normalized_api_base,
                false,
            ),
        ] {
            if matches {
                executions.set(executions.get() + 1);
            }
        }
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn audit_ipc_codec_rejects_oversized_length_header_before_body() {
        let oversized = AUDIT_CAPABILITY_MAX_IPC_BYTES + 1;
        let encoded = ((oversized as u32) << 2) | 0x2;
        let mut header = BytesMut::from(&encoded.to_le_bytes()[..3]);
        let mut codec = hbb_common::bytes_codec::BytesCodec::new();
        codec.set_max_packet_length(AUDIT_CAPABILITY_MAX_IPC_BYTES);
        assert!(codec.decode(&mut header).is_err());
    }

    #[test]
    fn audit_ipc_protocol_never_serializes_account_credentials() {
        let request = AuditIpcRequest::Issue {
            ticket: AuditRemoteSessionTicket {
                launch_nonce: launch_nonce(),
                remote_session_id: "remote-session".to_owned(),
            },
            operation: AuditOperationRequest::WriteNote {
                guid: "guid".to_owned(),
                note: "note".to_owned(),
            },
        };
        let json = String::from_utf8(serialize_audit_ipc(&request).unwrap().to_vec()).unwrap();
        let lower = json.to_ascii_lowercase();
        for forbidden in ["access_token", "authorization", "bearer", "password"] {
            assert!(!lower.contains(forbidden));
        }
        assert!(!lower.contains("peer_id"));
        assert!(!lower.contains("connection_session_id"));
    }
}

/// 通用配置桥不得触碰权威认证、游标或待撤销状态。
pub fn option_bridge_allows_key(key: &str) -> bool {
    !crate::hbbs_http::auth_binding::is_protected_auth_option(key)
        && !crate::client::protected_peer_option_key(key)
}

/// 通用写桥除认证权威键外，也不得逐项发布服务器解析器输入。
pub fn option_bridge_allows_write_key(key: &str) -> bool {
    option_bridge_allows_key(key)
        && !crate::hbbs_http::auth_binding::is_server_authority_option(key)
}

fn remove_protected_options(options: &mut HashMap<String, String>) {
    options.retain(|key, _| option_bridge_allows_key(key));
}

fn contains_forbidden_write_option(options: &HashMap<String, String>) -> bool {
    options
        .keys()
        .any(|key| !option_bridge_allows_write_key(key.as_str()))
}

/// Flutter 通用 HTTP 桥只接受有限业务头，账号凭证只能由 strict transport 注入。
pub fn generic_http_headers_are_allowed(headers: &str) -> bool {
    if headers.trim().is_empty() {
        return true;
    }
    if headers.len() > 64 * 1024 {
        return false;
    }
    let Ok(headers) = serde_json::from_str::<HashMap<String, String>>(headers) else {
        return false;
    };
    if headers.len() > 32 {
        return false;
    }
    headers.iter().all(|(key, value)| {
        let key = key.trim().to_ascii_lowercase();
        !key.is_empty()
            && key.len() <= 256
            && value.len() <= 16 * 1024
            && !matches!(
                key.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "host"
            )
            && !key.chars().any(char::is_control)
            && !value.chars().any(char::is_control)
    })
}

/// Sciter 通用 HTTP 桥只允许无裸请求头调用。
pub fn sciter_generic_headers_are_allowed(headers: &str) -> bool {
    headers.trim().is_empty()
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerConfigPublishResult {
    pub base_changed: bool,
    pub session_invalidated: bool,
    pub snapshot: crate::hbbs_http::auth_binding::AuthSnapshot,
}

fn validate_server_config_input(name: &str, value: &str, max_bytes: usize) -> ResultType<()> {
    if value.len() > max_bytes || value.contains('\0') || value.chars().any(char::is_control) {
        hbb_common::bail!("{name} 配置值无效");
    }
    Ok(())
}

fn effective_api_server_from_options(options: &HashMap<String, String>) -> String {
    crate::get_api_server(
        options.get("api-server").cloned().unwrap_or_default(),
        options
            .get("custom-rendezvous-server")
            .cloned()
            .unwrap_or_default(),
    )
}

fn current_ui_options_snapshot() -> HashMap<String, String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let mut options = OPTIONS.lock().unwrap().clone();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut options = Config::get_options();
    remove_protected_options(&mut options);
    options
}

fn current_auth_device_identity() -> crate::hbbs_http::auth_binding::DeviceIdentitySnapshot {
    #[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
    let id = get_id();
    #[cfg(all(
        not(any(target_os = "android", target_os = "ios")),
        not(feature = "flutter")
    ))]
    let id = ipc::get_id();
    let uuid = get_uuid();
    let valid = !id.is_empty()
        && !uuid.is_empty()
        && id.chars().count() <= 100
        && !id.chars().any(char::is_control)
        && uuid.len() <= 512
        && !uuid.chars().any(char::is_control);
    if valid {
        crate::hbbs_http::auth_binding::DeviceIdentitySnapshot { id, uuid }
    } else {
        crate::hbbs_http::auth_binding::DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        }
    }
}

fn notify_server_config_auth_invalidation(
    previous: Option<crate::hbbs_http::auth_binding::AuthSessionSnapshot>,
    result: &ServerConfigPublishResult,
    source: &str,
) {
    #[cfg(not(feature = "flutter"))]
    let _ = (&previous, source);
    if !result.session_invalidated {
        return;
    }
    #[cfg(feature = "flutter")]
    crate::hbbs_http::address_book_sync::wake_worker();
    #[cfg(feature = "flutter")]
    if let Some(previous) = previous {
        let event = serde_json::json!({
            "name": "native_auth_cleared",
            "reason": "server_config_changed",
            "source": source,
            "cleared_session_epoch": previous.session_epoch,
            "cleared_session_nonce": previous.session_nonce,
            "auth_epoch": result.snapshot.auth_epoch,
            "logout_generation": result.snapshot.logout_generation,
        });
        let _ = crate::flutter::push_global_event(crate::flutter::APP_TYPE_MAIN, event.to_string());
    }
}

fn lock_server_config_publish() -> ResultType<std::sync::MutexGuard<'static, ()>> {
    SERVER_CONFIG_PUBLISH_LOCK
        .lock()
        .map_err(|_| hbb_common::anyhow::anyhow!("服务器配置发布锁已损坏"))
}

#[cfg(test)]
mod issue9_server_config_publish_lock_tests {
    use super::lock_server_config_publish;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    };

    #[test]
    fn auth_begin_reads_base_only_after_pending_publish_completes() {
        let publish_guard = lock_server_config_publish().expect("应取得配置发布锁");
        let candidate = Arc::new(Mutex::new("https://a.example.com".to_owned()));
        let sender_count = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread_candidate = candidate.clone();
        let thread_sender_count = sender_count.clone();
        let begin = std::thread::spawn(move || {
            ready_tx.send(()).expect("应通知 begin 已就绪");
            let _guard = lock_server_config_publish().expect("begin 应等待配置发布完成");
            let observed = thread_candidate.lock().unwrap().clone();
            if observed == "https://a.example.com" {
                thread_sender_count.fetch_add(1, Ordering::SeqCst);
            }
            observed
        });
        ready_rx.recv().expect("应收到 begin 就绪通知");

        *candidate.lock().unwrap() = "https://b.example.com".to_owned();
        drop(publish_guard);

        assert_eq!(
            begin.join().expect("begin 线程不应失败"),
            "https://b.example.com"
        );
        assert_eq!(sender_count.load(Ordering::SeqCst), 0);
    }
}

fn reconcile_server_options_before_publish(
    current: &HashMap<String, String>,
    candidate: &HashMap<String, String>,
) -> ResultType<(
    ServerConfigPublishResult,
    Option<crate::hbbs_http::auth_binding::AuthSessionSnapshot>,
)> {
    crate::hbbs_http::auth_binding::require_trusted_main_ui_process()?;
    let previous = crate::hbbs_http::auth_binding::auth_snapshot()?.session;
    let transition = crate::hbbs_http::auth_binding::reconcile_effective_api_base_before_publish(
        &effective_api_server_from_options(current),
        &effective_api_server_from_options(candidate),
        current_auth_device_identity(),
    )?;
    Ok((
        ServerConfigPublishResult {
            base_changed: transition.base_changed,
            session_invalidated: transition.session_invalidated,
            snapshot: transition.snapshot,
        },
        previous,
    ))
}

/// 主界面唯一允许发布四个服务器解析器输入的入口。
pub fn stage_and_publish_server_config(
    id_server: String,
    relay_server: String,
    api_server: String,
    key: String,
) -> ResultType<ServerConfigPublishResult> {
    validate_server_config_input("ID Server", &id_server, 4096)?;
    validate_server_config_input("Relay Server", &relay_server, 4096)?;
    validate_server_config_input("API Server", &api_server, 8192)?;
    validate_server_config_input("Key", &key, 16 * 1024)?;
    let _publish_guard = lock_server_config_publish()?;
    let current = current_ui_options_snapshot();
    let mut candidate = current.clone();
    for (name, value) in [
        ("custom-rendezvous-server", id_server),
        ("relay-server", relay_server),
        ("api-server", api_server),
        ("key", key),
    ] {
        if value.is_empty() {
            candidate.remove(name);
        } else {
            candidate.insert(name.to_owned(), value);
        }
    }
    let (result, previous) = reconcile_server_options_before_publish(&current, &candidate)?;

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        ipc::set_options(candidate.clone())?;
        *OPTIONS.lock().unwrap() = candidate;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::set_options(candidate);

    notify_server_config_auth_invalidation(previous, &result, "typed_server_config");
    Ok(result)
}

/// 接收 daemon/root 的完整 Options 快照；若主界面已持有认证，先持久化失效再发布。
pub fn accept_authoritative_options(mut candidate: HashMap<String, String>) -> ResultType<()> {
    remove_protected_options(&mut candidate);
    let _publish_guard = lock_server_config_publish()?;
    let current = current_ui_options_snapshot();
    let transition = if crate::hbbs_http::auth_binding::is_main_ui_auth_initialized() {
        Some(reconcile_server_options_before_publish(
            &current, &candidate,
        )?)
    } else {
        None
    };

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        *OPTIONS.lock().unwrap() = candidate;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::set_options(candidate);

    if let Some((result, previous)) = transition {
        notify_server_config_auth_invalidation(previous, &result, "ipc_options");
    }
    Ok(())
}

/// installed desktop 必须先收到 daemon/root 的首个权威 Options，再打开认证状态。
pub fn wait_for_authoritative_options_before_auth(timeout: Duration) -> ResultType<()> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if !crate::platform::is_installed() {
            return Ok(());
        }
        start_option_status_sync();
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            if *OPTION_SYNCED
                .lock()
                .map_err(|_| hbb_common::anyhow::anyhow!("Options 同步状态锁已损坏"))?
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        hbb_common::bail!("等待 daemon/root 权威服务器配置超时");
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = timeout;
        Ok(())
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn initialize_sciter_auth() -> bool {
    auth_binding::scrub_legacy_auth_mirror();
    let result = wait_for_authoritative_options_before_auth(Duration::from_secs(5))
        .and_then(|_| AuthAuthorityAnchor::for_current_install())
        .and_then(auth_binding::initialize_main_ui_auth)
        .and_then(|_| {
            let effective = get_api_server();
            auth_binding::reconcile_effective_api_base_before_publish(
                &effective,
                &effective,
                current_auth_device_identity(),
            )
            .map(|_| ())
        });
    if result.is_err() {
        set_sciter_auth_error_without_job("本地认证状态不可用，请重启主界面后重试");
        return false;
    }
    ensure_audit_capability_ipc_server_started();
    if let Ok(tickets) = auth_binding::pending_logout_tickets() {
        for ticket in tickets {
            std::thread::spawn(move || {
                retry_sciter_pending_logout_until_terminal(ticket);
            });
        }
    }
    true
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn get_sciter_auth_snapshot() -> String {
    match auth_binding::auth_snapshot() {
        Ok(snapshot) => {
            let session = snapshot.session.map(|session| {
                serde_json::json!({
                    "normalized_api_base": session.normalized_api_base,
                    "namespace": session.namespace,
                    "session_epoch": session.session_epoch,
                    "session_nonce": session.session_nonce,
                    "user": sciter_safe_user_value(&session.safe_user),
                })
            });
            serde_json::json!({
                "authenticated": session.is_some(),
                "session": session,
                "pending_logout_count": snapshot.pending_logout_count,
            })
            .to_string()
        }
        Err(_) => serde_json::json!({
            "authenticated": false,
            "session": null,
            "error": "本地认证状态不可用",
        })
        .to_string(),
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn start_sciter_auth_login(
    login_body: String,
    attempt_json: String,
    parent_job_id: String,
) -> String {
    let Ok(login_body) = prepare_sciter_login_body(&login_body) else {
        return String::new();
    };
    let continuation = if attempt_json.is_empty() {
        if !parent_job_id.is_empty() {
            return String::new();
        }
        None
    } else {
        let Ok(attempt) = parse_sciter_auth_attempt(&attempt_json) else {
            return String::new();
        };
        let Some(parent_job_id) = parse_sciter_auth_job_id(&parent_job_id) else {
            return String::new();
        };
        Some((parent_job_id, attempt))
    };
    // 首次 begin 必须在配置发布锁内读取 authoritative base，并保持 publish→Sciter→auth 锁序。
    let publish_guard = if continuation.is_none() {
        match lock_server_config_publish() {
            Ok(guard) => Some(guard),
            Err(_) => return String::new(),
        }
    } else {
        None
    };
    let Ok(_start_guard) = SCITER_AUTH_START_MUTEX.lock() else {
        return String::new();
    };
    if continuation
        .as_ref()
        .is_some_and(|(_, attempt)| !auth_binding::is_auth_attempt_current(attempt))
    {
        return String::new();
    }
    let (job_id, attempt) = match continuation {
        Some((parent_job_id, attempt)) => {
            let job_id = match begin_sciter_auth_job(Some((parent_job_id, &attempt))) {
                Ok(job_id) => job_id,
                Err(_) => return String::new(),
            };
            (job_id, attempt)
        }
        None => {
            let attempt = match auth_binding::begin_auth_attempt(&get_api_server()) {
                Ok(attempt) => attempt,
                Err(_) => return String::new(),
            };
            let job_id = match begin_sciter_auth_job(None) {
                Ok(job_id) => job_id,
                Err(_) => {
                    let _ = auth_binding::cancel_auth_attempt(&attempt);
                    return String::new();
                }
            };
            (job_id, attempt)
        }
    };
    if !bind_sciter_auth_attempt(job_id, &attempt) {
        let _ = auth_binding::cancel_auth_attempt(&attempt);
        finish_sciter_auth_job(
            job_id,
            serde_json::json!({"kind": "stale"}).to_string(),
            Some(SciterAuthGuard::Attempt(attempt)),
        );
        return job_id.to_string();
    }
    drop(publish_guard);
    let worker_attempt = attempt.clone();
    std::thread::spawn(move || run_sciter_auth_login(job_id, login_body, worker_attempt));
    job_id.to_string()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn cancel_sciter_auth_attempt(attempt_json: String) -> bool {
    let Ok(attempt) = parse_sciter_auth_attempt(&attempt_json) else {
        return false;
    };
    match auth_binding::cancel_auth_attempt(&attempt) {
        Ok(cancelled) => cancelled,
        Err(_) => {
            log::warn!("Sciter auth attempt cancellation failed");
            false
        }
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn start_sciter_auth_request(operation: String, body: String) -> String {
    let Some(operation) = SciterSessionOperation::parse(&operation) else {
        return String::new();
    };
    let Ok(_start_guard) = SCITER_AUTH_START_MUTEX.lock() else {
        return String::new();
    };
    let job_id = match begin_sciter_auth_job(None) {
        Ok(job_id) => job_id,
        Err(_) => return String::new(),
    };
    std::thread::spawn(move || run_sciter_auth_request(job_id, operation, body));
    job_id.to_string()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn start_sciter_auth_logout() -> String {
    let Ok(_start_guard) = SCITER_AUTH_START_MUTEX.lock() else {
        return String::new();
    };
    let job_id = match begin_sciter_auth_job(None) {
        Ok(job_id) => job_id,
        Err(_) => return String::new(),
    };
    let identity = sciter_device_identity();
    let ticket = match auth_binding::begin_logout_current(identity) {
        Ok(ticket) => ticket,
        Err(_) => {
            finish_sciter_auth_job(
                job_id,
                sciter_error_json("error", None, "本地注销失败，认证状态未改变"),
                None,
            );
            return job_id.to_string();
        }
    };
    let Some(ticket) = ticket else {
        finish_sciter_auth_job(
            job_id,
            serde_json::json!({"kind": "logged_out"}).to_string(),
            None,
        );
        return job_id.to_string();
    };
    std::thread::spawn(move || {
        let outcome = auth_binding::retry_pending_logout_blocking(&ticket);
        let retained = matches!(&outcome, Ok(PendingLogoutOutcome::Retained { .. }));
        let payload = match outcome {
            Ok(PendingLogoutOutcome::Revoked | PendingLogoutOutcome::Missing) => {
                serde_json::json!({"kind": "logged_out"}).to_string()
            }
            Ok(PendingLogoutOutcome::UnsupportedLocalOnly) => serde_json::json!({
                "kind": "logged_out_local_only",
                "message": "服务器不支持远端注销，本机认证状态已安全清除",
            })
            .to_string(),
            Ok(PendingLogoutOutcome::Retained { .. }) | Err(_) => serde_json::json!({
                "kind": "logout_pending",
                "message": "本机已注销，远端撤销将在安全通道可用后重试",
            })
            .to_string(),
        };
        finish_sciter_auth_job(job_id, payload, None);
        if retained {
            retry_sciter_pending_logout_until_terminal(ticket);
        }
    });
    job_id.to_string()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub fn get_sciter_auth_job_status(job_id: String) -> String {
    let Some(job_id) = parse_sciter_auth_job_id(&job_id) else {
        return serde_json::json!({"kind": "stale"}).to_string();
    };
    let (status, guard) = {
        let job = SCITER_AUTH_JOB.lock().unwrap();
        let Some(snapshot) = sciter_job_snapshot(&job, job_id) else {
            return serde_json::json!({"kind": "stale"}).to_string();
        };
        snapshot
    };
    let current = match guard.as_ref() {
        Some(SciterAuthGuard::Attempt(attempt)) => auth_binding::is_auth_attempt_current(attempt),
        Some(SciterAuthGuard::Session(handle)) => auth_binding::is_request_current(handle),
        None => true,
    };
    if !current {
        return serde_json::json!({"kind": "stale"}).to_string();
    }
    status
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn begin_sciter_auth_job(continuation: Option<(u64, &AuthAttempt)>) -> ResultType<u64> {
    let mut job = SCITER_AUTH_JOB
        .lock()
        .map_err(|_| anyhow!("Sciter auth job lock is poisoned"))?;
    if let Some((parent_job_id, attempt)) = continuation {
        if !sciter_job_allows_continuation(&job, parent_job_id, attempt) {
            hbb_common::bail!("Sciter auth continuation owner is stale");
        }
    }
    let next_id = job
        .next_id
        .checked_add(1)
        .filter(|value| *value <= SCITER_AUTH_MAX_SAFE_INTEGER)
        .ok_or_else(|| anyhow!("Sciter auth job counter is exhausted"))?;
    job.next_id = next_id;
    job.active_id = next_id;
    job.status = INIT_ASYNC_JOB_STATUS.to_owned();
    job.guard = continuation.map(|(_, attempt)| SciterAuthGuard::Attempt(attempt.clone()));
    Ok(next_id)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn finish_sciter_auth_job(job_id: u64, status: String, guard: Option<SciterAuthGuard>) {
    let Ok(mut job) = SCITER_AUTH_JOB.lock() else {
        return;
    };
    if job.active_id != job_id {
        return;
    }
    job.status = status;
    job.guard = guard;
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn set_sciter_auth_error_without_job(message: &str) {
    let Ok(mut job) = SCITER_AUTH_JOB.lock() else {
        return;
    };
    if let Some(next_id) = job
        .next_id
        .checked_add(1)
        .filter(|value| *value <= SCITER_AUTH_MAX_SAFE_INTEGER)
    {
        job.next_id = next_id;
        job.active_id = next_id;
    }
    job.status = sciter_error_json("error", None, message);
    job.guard = None;
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn parse_sciter_auth_attempt(attempt_json: &str) -> ResultType<AuthAttempt> {
    if attempt_json.is_empty() || attempt_json.len() > SCITER_AUTH_MAX_ATTEMPT_BYTES {
        hbb_common::bail!("Sciter auth attempt size is invalid");
    }
    let attempt: AuthAttempt =
        serde_json::from_str(attempt_json).context("Sciter auth attempt is invalid")?;
    if attempt.attempt_id == 0
        || attempt.attempt_id > SCITER_AUTH_MAX_SAFE_INTEGER
        || attempt.logout_generation > SCITER_AUTH_MAX_SAFE_INTEGER
        || attempt.nonce.is_empty()
        || attempt.nonce.len() > SCITER_AUTH_MAX_SAFE_TEXT_BYTES
        || attempt.nonce.chars().any(char::is_control)
        || attempt.normalized_api_base.is_empty()
        || attempt.normalized_api_base.len() > SCITER_AUTH_MAX_SAFE_TEXT_BYTES
        || attempt.normalized_api_base.chars().any(char::is_control)
    {
        hbb_common::bail!("Sciter auth attempt fields are invalid");
    }
    Ok(attempt)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn parse_sciter_auth_job_id(job_id: &str) -> Option<u64> {
    if job_id.is_empty() || job_id.len() > 16 || !job_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    job_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= SCITER_AUTH_MAX_SAFE_INTEGER)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_value_contains_native_field(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            key.to_ascii_lowercase().starts_with("native_")
                || sciter_value_contains_native_field(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(sciter_value_contains_native_field),
        _ => false,
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn prepare_sciter_login_body(login_body: &str) -> ResultType<String> {
    if login_body.is_empty() || login_body.len() > SCITER_AUTH_MAX_LOGIN_BODY_BYTES {
        hbb_common::bail!("Sciter login body size is invalid");
    }
    let value: serde_json::Value =
        serde_json::from_str(login_body).context("Sciter login body is invalid")?;
    if !value.is_object() {
        hbb_common::bail!("Sciter login body must be an object");
    }
    if sciter_value_contains_native_field(&value) {
        hbb_common::bail!("Sciter login body contains a reserved native field");
    }
    serde_json::to_string(&value).context("Sciter login body could not be serialized")
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_job_owns_attempt(job: &SciterAuthJob, job_id: u64, attempt: &AuthAttempt) -> bool {
    job.active_id == job_id
        && matches!(
            job.guard.as_ref(),
            Some(SciterAuthGuard::Attempt(current)) if current == attempt
        )
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_job_snapshot(
    job: &SciterAuthJob,
    expected_job_id: u64,
) -> Option<(String, Option<SciterAuthGuard>)> {
    (job.active_id == expected_job_id).then(|| (job.status.clone(), job.guard.clone()))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_job_allows_continuation(
    job: &SciterAuthJob,
    parent_job_id: u64,
    attempt: &AuthAttempt,
) -> bool {
    sciter_job_owns_attempt(job, parent_job_id, attempt)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn bind_sciter_auth_attempt(job_id: u64, attempt: &AuthAttempt) -> bool {
    let Ok(mut job) = SCITER_AUTH_JOB.lock() else {
        return false;
    };
    if job.active_id != job_id || job.status != INIT_ASYNC_JOB_STATUS {
        return false;
    }
    match job.guard.as_ref() {
        None => job.guard = Some(SciterAuthGuard::Attempt(attempt.clone())),
        Some(SciterAuthGuard::Attempt(current)) if current == attempt => {}
        _ => return false,
    }
    true
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_auth_attempt_is_current_for_job(job_id: u64, attempt: &AuthAttempt) -> bool {
    let owned_before = SCITER_AUTH_JOB
        .lock()
        .map(|job| sciter_job_owns_attempt(&job, job_id, attempt))
        .unwrap_or(false);
    if !owned_before || !auth_binding::is_auth_attempt_current(attempt) {
        return false;
    }
    SCITER_AUTH_JOB
        .lock()
        .map(|job| sciter_job_owns_attempt(&job, job_id, attempt))
        .unwrap_or(false)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn execute_sciter_login_if_current<T>(
    attempt: &AuthAttempt,
    is_current: impl FnOnce(&AuthAttempt) -> bool,
    execute: impl FnOnce() -> ResultType<T>,
) -> ResultType<T> {
    if !is_current(attempt) {
        hbb_common::bail!("Sciter auth attempt is stale");
    }
    execute()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn run_sciter_auth_login(job_id: u64, login_body: String, attempt: AuthAttempt) {
    let attempt_guard = Some(SciterAuthGuard::Attempt(attempt.clone()));
    let result = (|| -> ResultType<(String, Option<SciterAuthGuard>)> {
        let login_url = sciter_endpoint_under_base(&attempt.normalized_api_base, "api/login")?;
        let response = execute_sciter_login_if_current(
            &attempt,
            |attempt| sciter_auth_attempt_is_current_for_job(job_id, attempt),
            || {
                strict_http_request_no_bearer_blocking(
                    RequestSecurityClass::LoginStrict,
                    StrictHttpRequest::new(StrictHttpMethod::Post, login_url).json_body(login_body),
                )
            },
        )?;
        if !sciter_auth_attempt_is_current_for_job(job_id, &attempt) {
            hbb_common::bail!("Sciter auth attempt is stale");
        }
        if !(200..300).contains(&response.status) {
            return Ok((
                sciter_error_json("http_error", Some(response.status), "登录失败"),
                attempt_guard.clone(),
            ));
        }
        require_sciter_json_content_type(response.content_type.as_deref())?;
        let serde_json::Value::Object(mut body) =
            serde_json::from_str::<serde_json::Value>(&response.body)
                .context("Sciter login response is invalid")?
        else {
            hbb_common::bail!("Sciter login response must be an object");
        };
        let response_type = sciter_safe_text(&body, "type")?;
        if response_type == "access_token" {
            let access_token = body
                .remove("access_token")
                .and_then(|value| value.as_str().map(str::to_owned))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Sciter login response is missing a credential"))?;
            let safe_user = body
                .get("user")
                .ok_or_else(|| anyhow!("Sciter login response is missing user data"))
                .and_then(parse_sciter_safe_user)?;
            let _commit_guard = SCITER_AUTH_START_MUTEX
                .lock()
                .map_err(|_| anyhow!("Sciter auth start lock is poisoned"))?;
            if !sciter_auth_attempt_is_current_for_job(job_id, &attempt) {
                hbb_common::bail!("Sciter auth attempt is stale");
            }
            let snapshot = auth_binding::commit_auth_attempt(
                &attempt,
                access_token,
                safe_user,
                sciter_login_expiry_hint(&body),
            )?;
            drop(_commit_guard);
            let session = snapshot
                .session
                .ok_or_else(|| anyhow!("Sciter auth commit did not create a session"))?;
            let guard_url =
                sciter_endpoint_under_base(&session.normalized_api_base, "api/currentUser")?;
            let handle = auth_binding::credentialed_request_handle(&guard_url)?;
            return Ok((
                serde_json::json!({
                    "kind": "authenticated",
                    "status": response.status,
                    "user": sciter_safe_user_value(&session.safe_user),
                    "session_epoch": session.session_epoch,
                    "session_nonce": session.session_nonce,
                    "namespace": session.namespace,
                })
                .to_string(),
                Some(SciterAuthGuard::Session(handle)),
            ));
        }
        let tfa_type = sciter_safe_text(&body, "tfa_type")?;
        let challenge_type = if response_type.is_empty() {
            tfa_type.clone()
        } else {
            response_type.clone()
        };
        if challenge_type.is_empty() {
            hbb_common::bail!("Sciter login response is not a supported challenge");
        }
        let secret = sciter_safe_text(&body, "secret")?;
        let user = body
            .get("user")
            .filter(|value| !value.is_null())
            .map(parse_sciter_safe_user)
            .transpose()?;
        let challenge_user = user.map(|user| {
            serde_json::json!({
                "id": user.id,
                "name": user.name,
                "email": user.email,
            })
        });
        let native_attempt = serde_json::to_string(&attempt)
            .context("Sciter auth attempt could not be serialized")?;
        Ok((
            serde_json::json!({
                "kind": "challenge",
                "status": response.status,
                "challenge_type": challenge_type,
                "type": response_type,
                "tfa_type": tfa_type,
                "secret": secret,
                "user": challenge_user,
                "native_attempt": native_attempt,
                "native_job_id": job_id.to_string(),
            })
            .to_string(),
            attempt_guard.clone(),
        ))
    })();
    match result {
        Ok((payload, guard)) => finish_sciter_auth_job(job_id, payload, guard),
        Err(_) => finish_sciter_auth_job(
            job_id,
            sciter_error_json("error", None, "认证请求失败"),
            attempt_guard,
        ),
    }
}

#[cfg(all(
    test,
    not(any(
        target_os = "android",
        target_os = "ios",
        feature = "flutter",
        feature = "cli"
    ))
))]
mod issue9_sciter_attempt_tests {
    use super::*;
    use std::cell::Cell;

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustdesk-sciter-attempt-{}",
                hbb_common::uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).expect("应创建 Sciter attempt 测试目录");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn issue9_sciter_auth旧挑战在新登录后不会发出网络请求() {
        let root = TestRoot::new();
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(&root.0, b"issue9-sciter-attempt-install")
                .expect("应创建 Sciter auth authority");
        let mut binding =
            auth_binding::AuthBinding::open(authority).expect("应打开 Sciter auth binding");
        let attempt_a = binding
            .begin_auth_attempt("https://a.example.com")
            .expect("应开始 A 登录");
        let attempt_b = binding
            .begin_auth_attempt("https://b.example.com")
            .expect("应开始 B 登录");
        let request_count = Cell::new(0usize);

        let stale = execute_sciter_login_if_current(
            &attempt_a,
            |attempt| binding.is_auth_attempt_current(attempt),
            || {
                request_count.set(request_count.get() + 1);
                Ok(())
            },
        );
        assert!(stale.is_err());
        assert_eq!(request_count.get(), 0);
        assert!(binding.is_auth_attempt_current(&attempt_b));

        execute_sciter_login_if_current(
            &attempt_b,
            |attempt| binding.is_auth_attempt_current(attempt),
            || {
                request_count.set(request_count.get() + 1);
                Ok(())
            },
        )
        .expect("当前 B 登录应允许发出请求");
        assert_eq!(request_count.get(), 1);
    }

    #[test]
    fn issue9_sciter_auth旧任务在新任务尚未创建_attempt_时也不会发请求() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            &root.0,
            b"issue9-sciter-job-replacement-install",
        )
        .expect("应创建 Sciter job replacement authority");
        let mut binding =
            auth_binding::AuthBinding::open(authority).expect("应打开 Sciter auth binding");
        let attempt_a = binding
            .begin_auth_attempt("https://a.example.com")
            .expect("应开始 A 登录");
        let replacement_job = SciterAuthJob {
            next_id: 2,
            active_id: 2,
            status: INIT_ASYNC_JOB_STATUS.to_owned(),
            guard: None,
        };
        let request_count = Cell::new(0usize);

        let stale = execute_sciter_login_if_current(
            &attempt_a,
            |attempt| {
                sciter_job_owns_attempt(&replacement_job, 1, attempt)
                    && binding.is_auth_attempt_current(attempt)
            },
            || {
                request_count.set(request_count.get() + 1);
                Ok(())
            },
        );
        assert!(stale.is_err());
        assert_eq!(request_count.get(), 0);
        assert!(binding.is_auth_attempt_current(&attempt_a));
    }

    #[test]
    fn issue9_sciter_auth能力原样往返并拒绝未知字段() {
        let attempt = AuthAttempt {
            attempt_id: 7,
            nonce: "issue9-sciter-attempt-nonce".to_owned(),
            normalized_api_base: "https://example.com".to_owned(),
            logout_generation: 3,
        };
        let encoded = serde_json::to_string(&attempt).expect("应序列化 Sciter attempt");
        assert_eq!(parse_sciter_auth_attempt(&encoded).unwrap(), attempt);

        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["unexpected"] = serde_json::Value::Bool(true);
        assert!(parse_sciter_auth_attempt(&tampered.to_string()).is_err());
    }

    #[test]
    fn issue9_sciter_auth递归拒绝大小写变体的原生保留字段() {
        for body in [
            r#"{"native_attempt":"forged"}"#,
            r#"{"Native_Attempt":"forged"}"#,
            r#"{"deviceInfo":{"NATIVE_job_id":"forged"}}"#,
            r#"{"items":[{"native_secret":"forged"}]}"#,
        ] {
            assert!(prepare_sciter_login_body(body).is_err(), "{body}");
        }
        let normalized = prepare_sciter_login_body(
            r#"{ "username": "alice", "deviceInfo": {"name": "desktop"} }"#,
        )
        .expect("合法登录请求应被重新序列化");
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value["username"], "alice");
        assert!(!sciter_value_contains_native_field(&value));
    }

    #[test]
    fn issue9_sciter_auth任务所有者必须同时匹配_job_id_与_attempt() {
        let attempt = AuthAttempt {
            attempt_id: 9,
            nonce: "issue9-job-owner-nonce".to_owned(),
            normalized_api_base: "https://example.com".to_owned(),
            logout_generation: 4,
        };
        let job = SciterAuthJob {
            next_id: 12,
            active_id: 12,
            status: INIT_ASYNC_JOB_STATUS.to_owned(),
            guard: Some(SciterAuthGuard::Attempt(attempt.clone())),
        };
        assert!(sciter_job_owns_attempt(&job, 12, &attempt));
        assert!(sciter_job_allows_continuation(&job, 12, &attempt));
        assert!(!sciter_job_owns_attempt(&job, 11, &attempt));
        assert!(!sciter_job_allows_continuation(&job, 11, &attempt));
        assert!(sciter_job_snapshot(&job, 12).is_some());
        assert!(sciter_job_snapshot(&job, 11).is_none());

        let mut forged = attempt.clone();
        forged.nonce = "forged".to_owned();
        assert!(!sciter_job_owns_attempt(&job, 12, &forged));
        assert_eq!(parse_sciter_auth_job_id("12"), Some(12));
        assert_eq!(parse_sciter_auth_job_id("0"), None);
        assert_eq!(parse_sciter_auth_job_id("12.0"), None);
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn run_sciter_auth_request(job_id: u64, operation: SciterSessionOperation, body: String) {
    let mut session_guard = None;
    let result = (|| -> ResultType<(String, Option<SciterAuthGuard>)> {
        if body.len() > SCITER_AUTH_MAX_SESSION_BODY_BYTES {
            hbb_common::bail!("Sciter authenticated request body is too large");
        }
        let serde_json::Value::Object(_) = serde_json::from_str::<serde_json::Value>(&body)
            .context("Sciter authenticated request body is invalid")?
        else {
            hbb_common::bail!("Sciter authenticated request body must be an object");
        };
        let snapshot = auth_binding::auth_snapshot()?;
        let session = snapshot
            .session
            .ok_or_else(|| anyhow!("Sciter authenticated request has no session"))?;
        let target =
            sciter_endpoint_under_base(&session.normalized_api_base, operation.endpoint())?;
        let handle = auth_binding::credentialed_request_handle(&target)?;
        session_guard = Some(SciterAuthGuard::Session(handle.clone()));
        let request_context = auth_binding::credentialed_context(&handle, &target)?;
        let response = strict_http_request_blocking(
            &handle,
            StrictHttpRequest::new(StrictHttpMethod::Post, target).json_body(body),
        )?;
        if response.body.contains(&request_context.access_token) {
            hbb_common::bail!("Sciter authenticated response contains a session credential");
        }
        if response.status == 401 {
            let _ = auth_binding::clear_auth_session_if_current(&handle)?;
            return Ok((
                sciter_error_json("http_error", Some(401), "认证已失效，请重新登录"),
                None,
            ));
        }
        if !(200..300).contains(&response.status) {
            return Ok((
                sciter_error_json("http_error", Some(response.status), "认证请求被服务器拒绝"),
                session_guard.clone(),
            ));
        }
        if response.status == 204 || response.body.trim().is_empty() {
            return Ok((
                serde_json::json!({
                    "kind": "response",
                    "status": response.status,
                    "data": {},
                })
                .to_string(),
                session_guard.clone(),
            ));
        }
        require_sciter_json_content_type(response.content_type.as_deref())?;
        let data: serde_json::Value =
            serde_json::from_str(&response.body).context("Sciter response is invalid")?;
        let data = if operation == SciterSessionOperation::CurrentUser {
            let safe_user = parse_sciter_safe_user(&data)?;
            if !crate::verify_login(&safe_user.verifier, &request_context.access_token) {
                hbb_common::bail!("Sciter current-user verifier is invalid");
            }
            sciter_safe_user_value(&safe_user)
        } else {
            data
        };
        Ok((
            serde_json::json!({
                "kind": "response",
                "status": response.status,
                "data": data,
            })
            .to_string(),
            session_guard.clone(),
        ))
    })();
    match result {
        Ok((payload, guard)) => finish_sciter_auth_job(job_id, payload, guard),
        Err(_) => finish_sciter_auth_job(
            job_id,
            sciter_error_json("error", None, "认证请求失败"),
            session_guard,
        ),
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_endpoint_under_base(base: &str, suffix: &str) -> ResultType<String> {
    let mut url = url::Url::parse(base).context("Sciter API base is invalid")?;
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/{}", suffix.trim_start_matches('/')));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn require_sciter_json_content_type(content_type: Option<&str>) -> ResultType<()> {
    let mime = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !mime.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        hbb_common::bail!("Sciter response Content-Type is invalid");
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_safe_text(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> ResultType<String> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(value))
            if value.len() <= SCITER_AUTH_MAX_SAFE_TEXT_BYTES
                && !value.chars().any(char::is_control) =>
        {
            Ok(value.clone())
        }
        Some(serde_json::Value::String(_)) => {
            hbb_common::bail!("Sciter response text is invalid")
        }
        Some(_) => hbb_common::bail!("Sciter response field type is invalid"),
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn parse_sciter_safe_user(value: &serde_json::Value) -> ResultType<AuthSafeUser> {
    let serde_json::Value::Object(user) = value else {
        hbb_common::bail!("Sciter response is missing safe user data");
    };
    let id = match user.get("id") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let id = value
                .as_u64()
                .filter(|id| *id > 0 && *id <= SCITER_AUTH_MAX_SAFE_INTEGER)
                .ok_or_else(|| anyhow!("Sciter user id is invalid"))?;
            Some(id)
        }
    };
    let name = sciter_safe_text(user, "name")?;
    if name.is_empty() {
        hbb_common::bail!("Sciter username is empty");
    }
    let status = match user.get("status") {
        None | Some(serde_json::Value::Null) => 1,
        Some(value) => value
            .as_i64()
            .ok_or_else(|| anyhow!("Sciter user status is invalid"))?,
    };
    let is_admin = match user.get("is_admin") {
        None | Some(serde_json::Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow!("Sciter admin flag is invalid"))?,
    };
    Ok(AuthSafeUser {
        id,
        name,
        display_name: sciter_safe_text(user, "display_name")?,
        avatar: sciter_safe_text(user, "avatar")?,
        email: sciter_safe_text(user, "email")?,
        note: sciter_safe_text(user, "note")?,
        status,
        is_admin,
        verifier: sciter_safe_text(user, "verifier")?,
    })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
pub(crate) fn sciter_safe_user_value(user: &AuthSafeUser) -> serde_json::Value {
    serde_json::json!({
        "id": user.id,
        "name": user.name,
        "display_name": user.display_name,
        "avatar": user.avatar,
        "status": user.status,
        "is_admin": user.is_admin,
    })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_login_expiry_hint(body: &serde_json::Map<String, serde_json::Value>) -> Option<i64> {
    if let Some(expires_at) = body.get("expires_at").and_then(serde_json::Value::as_i64) {
        return (expires_at > 0).then_some(expires_at);
    }
    let expires_in = body.get("expires_in").and_then(serde_json::Value::as_i64)?;
    if expires_in <= 0 {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(now.checked_add(expires_in as u64)?).ok()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_device_identity() -> DeviceIdentitySnapshot {
    let id = ipc::get_id();
    let uuid = get_uuid();
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

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn retry_sciter_pending_logout_until_terminal(ticket: auth_binding::PendingLogoutTicket) {
    loop {
        match auth_binding::retry_pending_logout_blocking(&ticket) {
            Ok(PendingLogoutOutcome::Retained {
                retry_after_unix_ms,
                ..
            }) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0);
                let wait_ms = retry_after_unix_ms.saturating_sub(now).clamp(50, 300_000);
                std::thread::sleep(Duration::from_millis(wait_ms));
            }
            Ok(
                PendingLogoutOutcome::Revoked
                | PendingLogoutOutcome::UnsupportedLocalOnly
                | PendingLogoutOutcome::Missing,
            )
            | Err(_) => return,
        }
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter",
    feature = "cli"
)))]
fn sciter_error_json(kind: &str, status: Option<u16>, message: &str) -> String {
    serde_json::json!({
        "kind": kind,
        "status": status,
        "message": message,
    })
    .to_string()
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_id() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_id();
}

#[inline]
pub fn goto_install() {
    allow_err!(crate::run_me(vec!["--install"]));
    std::process::exit(0);
}

#[inline]
pub fn install_me(_options: String, _path: String, _silent: bool, _debug: bool) {
    #[cfg(windows)]
    std::thread::spawn(move || {
        allow_err!(crate::platform::windows::install_me(
            &_options, _path, _silent, _debug
        ));
        std::process::exit(0);
    });
}

#[inline]
pub fn update_me(_path: String) {
    goto_install();
}

#[inline]
pub fn run_without_install() {
    crate::run_me(vec!["--noinstall"]).ok();
    std::process::exit(0);
}

#[inline]
pub fn show_run_without_install() -> bool {
    let mut it = std::env::args();
    if let Some(tmp) = it.next() {
        if crate::is_setup(&tmp) {
            return it.next() == None;
        }
    }
    false
}

#[inline]
pub fn get_license() -> String {
    #[cfg(windows)]
    if let Ok(lic) = crate::platform::windows::get_license_from_exe_name() {
        #[cfg(feature = "flutter")]
        return format!("Key: {}\nHost: {}\nAPI: {}", lic.key, lic.host, lic.api);
        // default license format is html formed (sciter)
        #[cfg(not(feature = "flutter"))]
        return format!(
            "<br /> Key: {} <br /> Host: {} API: {}",
            lic.key, lic.host, lic.api
        );
    }
    Default::default()
}

#[inline]
pub fn refresh_options() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut options = Config::get_options();
        remove_protected_options(&mut options);
        *OPTIONS.lock().unwrap() = options;
    }
}

#[inline]
pub fn get_option<T: AsRef<str>>(key: T) -> String {
    if !option_bridge_allows_key(key.as_ref()) {
        log::warn!("通用配置桥拒绝读取受保护认证键");
        return String::new();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let map = OPTIONS.lock().unwrap();
        if let Some(v) = map.get(key.as_ref()) {
            v.to_owned()
        } else {
            "".to_owned()
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        Config::get_option(key.as_ref())
    }
}

#[inline]
pub fn use_texture_render() -> bool {
    #[cfg(target_os = "android")]
    return false;
    #[cfg(target_os = "ios")]
    return false;

    #[cfg(target_os = "macos")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";

    #[cfg(target_os = "linux")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N";

    #[cfg(target_os = "windows")]
    {
        if !cfg!(feature = "flutter") {
            return false;
        }
        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1
        #[cfg(debug_assertions)]
        let default_texture = true;
        #[cfg(not(debug_assertions))]
        let default_texture = crate::platform::is_win_10_or_greater();
        if default_texture {
            LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N"
        } else {
            return LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";
        }
    }
}

#[inline]
pub fn is_option_fixed(key: &str) -> bool {
    config::OVERWRITE_DISPLAY_SETTINGS
        .read()
        .unwrap()
        .contains_key(key)
        || config::OVERWRITE_LOCAL_SETTINGS
            .read()
            .unwrap()
            .contains_key(key)
        || config::OVERWRITE_SETTINGS.read().unwrap().contains_key(key)
}

#[inline]
pub fn get_local_option(key: String) -> String {
    if !option_bridge_allows_key(&key) {
        log::warn!("通用本地配置桥拒绝读取受保护认证键");
        return String::new();
    }
    crate::get_local_option(&key)
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_hard_option(key: String) -> String {
    config::HARD_SETTINGS
        .read()
        .unwrap()
        .get(&key)
        .cloned()
        .unwrap_or_default()
}

#[inline]
pub fn get_builtin_option(key: &str) -> String {
    crate::get_builtin_option(key)
}

#[inline]
pub fn set_local_option(key: String, value: String) {
    if !option_bridge_allows_write_key(&key) {
        log::warn!("通用本地配置桥拒绝写入受保护权威键");
        return;
    }
    LocalConfig::set_option(key.clone(), value);
}

/// Resolve relative avatar path (e.g. "/avatar/xxx") to absolute URL
/// by prepending the API server address.
pub fn resolve_avatar_url(avatar: String) -> String {
    let avatar = avatar.trim().to_owned();
    if avatar.starts_with('/') {
        let api_server = get_api_server();
        if !api_server.is_empty() {
            return format!("{}{}", api_server.trim_end_matches('/'), avatar);
        }
    }
    avatar
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_local_flutter_option(key: String) -> String {
    if !option_bridge_allows_key(&key) {
        log::warn!("Flutter 通用配置桥拒绝读取受保护认证键");
        return String::new();
    }
    LocalConfig::get_flutter_option(&key)
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn set_local_flutter_option(key: String, value: String) {
    if !option_bridge_allows_write_key(&key) {
        log::warn!("Flutter 通用配置桥拒绝写入受保护权威键");
        return;
    }
    LocalConfig::set_flutter_option(key, value);
}

#[cfg(feature = "flutter")]
#[inline]
pub fn get_kb_layout_type() -> String {
    LocalConfig::get_kb_layout_type()
}

#[cfg(feature = "flutter")]
#[inline]
pub fn set_kb_layout_type(kb_layout_type: String) {
    LocalConfig::set_kb_layout_type(kb_layout_type);
}

#[inline]
pub fn peer_has_password(id: String) -> bool {
    crate::client::peer_config_has_explicit_password(&PeerConfig::load(&id))
}

#[inline]
pub fn forget_password(id: String) {
    let mut c = PeerConfig::load(&id);
    crate::client::clear_peer_config_password(&mut c);
    c.store(&id);
}

#[inline]
pub fn get_peer_option(id: String, name: String) -> String {
    if crate::client::protected_peer_option_key(&name) {
        return String::new();
    }
    let c = PeerConfig::load(&id);
    c.options.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_peer_flutter_option(id: String, name: String) -> String {
    let c = PeerConfig::load(&id);
    c.ui_flutter.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn set_peer_flutter_option(id: String, name: String, value: String) {
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.ui_flutter.remove(&name);
    } else {
        c.ui_flutter.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn set_peer_option(id: String, name: String, value: String) {
    if crate::client::protected_peer_option_key(&name) {
        log::warn!("通用对端配置桥拒绝写入受保护的密码来源标记");
        return;
    }
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.options.remove(&name);
    } else {
        c.options.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn get_options() -> String {
    let options = {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            OPTIONS.lock().unwrap()
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            Config::get_options()
        }
    };
    let mut m = serde_json::Map::new();
    for (k, v) in options.iter() {
        if !option_bridge_allows_key(k) {
            continue;
        }
        m.insert(k.into(), v.to_owned().into());
    }
    serde_json::to_string(&m).unwrap_or_default()
}

#[inline]
pub fn test_if_valid_server(host: String, test_with_proxy: bool) -> String {
    hbb_common::socket_client::test_if_valid_server(&host, test_with_proxy)
}

#[inline]
#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_sound_inputs() -> Vec<String> {
    let mut a = Vec::new();
    #[cfg(not(target_os = "linux"))]
    {
        fn get_sound_inputs_() -> Vec<String> {
            let mut out = Vec::new();
            use cpal::traits::{DeviceTrait, HostTrait};
            // Do not use `cpal::host_from_id(cpal::HostId::ScreenCaptureKit)` for feature = "screencapturekit"
            // Because we explicitly handle the "System Sound" device.
            let host = cpal::default_host();
            if let Ok(devices) = host.devices() {
                for device in devices {
                    if device.default_input_config().is_err() {
                        continue;
                    }
                    if let Ok(name) = device.name() {
                        out.push(name);
                    }
                }
            }
            out
        }

        let inputs = Arc::new(Mutex::new(Vec::new()));
        let cloned = inputs.clone();
        // can not call below in UI thread, because conflict with sciter sound com initialization
        std::thread::spawn(move || *cloned.lock().unwrap() = get_sound_inputs_())
            .join()
            .ok();
        for name in inputs.lock().unwrap().drain(..) {
            a.push(name);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let inputs: Vec<String> = crate::platform::linux::get_pa_sources()
            .drain(..)
            .map(|x| x.1)
            .collect();

        for name in inputs {
            a.push(name);
        }
    }
    a
}

#[inline]
pub fn set_options(m: HashMap<String, String>) {
    if contains_forbidden_write_option(&m) {
        log::warn!("通用配置桥拒绝包含受保护权威键的批量写入");
        return;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        *OPTIONS.lock().unwrap() = m.clone();
        ipc::set_options(m).ok();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::set_options(m);
}

#[inline]
pub fn set_option(key: String, value: String) {
    if !option_bridge_allows_write_key(&key) {
        log::warn!("通用配置桥拒绝写入受保护权威键");
        return;
    }
    if &key == "stop-service" {
        #[cfg(target_os = "macos")]
        {
            let is_stop = value == "Y";
            if is_stop && crate::platform::uninstall_service(true, false) {
                return;
            }
        }
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            if crate::platform::is_installed() {
                if value == "Y" {
                    if crate::platform::uninstall_service(true, false) {
                        return;
                    }
                } else {
                    if crate::platform::install_service() {
                        return;
                    }
                }
                return;
            }
        }
    } else if &key == "audio-input" {
        #[cfg(not(target_os = "ios"))]
        crate::audio_service::restart();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut options = OPTIONS.lock().unwrap();
        if value.is_empty() {
            options.remove(&key);
        } else {
            options.insert(key.clone(), value.clone());
        }
        ipc::set_options(options.clone()).ok();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _nat = crate::CheckTestNatType::new();
        Config::set_option(key, value);
    }
}

#[inline]
pub fn install_path() -> String {
    #[cfg(windows)]
    return crate::platform::windows::get_install_info().1;
    #[cfg(not(windows))]
    return "".to_owned();
}

#[inline]
pub fn install_options() -> String {
    #[cfg(windows)]
    return crate::platform::windows::get_install_options();
    #[cfg(not(windows))]
    return "{}".to_owned();
}

#[inline]
pub fn get_socks() -> Vec<String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let s = ipc::get_socks();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let s = Config::get_socks();
    match s {
        None => Vec::new(),
        Some(s) => {
            let mut v = Vec::new();
            v.push(s.proxy);
            v.push(s.username);
            v.push(s.password);
            v
        }
    }
}

#[inline]
pub fn set_socks(proxy: String, username: String, password: String) {
    let socks = config::Socks5Server {
        proxy,
        username,
        password,
    };
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::set_socks(socks).ok();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _nat = crate::CheckTestNatType::new();
        if socks.proxy.is_empty() {
            Config::set_socks(None);
        } else {
            Config::set_socks(Some(socks));
        }
        log::info!("socks updated");
    }
    #[cfg(target_os = "android")]
    {
        crate::RendezvousMediator::restart();
    }
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_proxy_status() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_proxy_status();

    // Currently, only the desktop version has proxy settings.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return false;
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_installed() -> bool {
    crate::platform::is_installed()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_installed() -> bool {
    false
}

#[inline]
pub fn is_share_rdp() -> bool {
    #[cfg(windows)]
    return crate::platform::windows::is_share_rdp();
    #[cfg(not(windows))]
    return false;
}

#[inline]
pub fn set_share_rdp(_enable: bool) {
    #[cfg(windows)]
    crate::platform::windows::set_share_rdp(_enable);
}

#[inline]
pub fn is_installed_lower_version() -> bool {
    #[cfg(not(windows))]
    return false;
    #[cfg(windows)]
    {
        let b = crate::platform::windows::get_reg("BuildDate");
        return crate::BUILD_DATE.cmp(&b).is_gt();
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_mouse_time() -> f64 {
    UI_STATUS.lock().unwrap().mouse_time as f64
}

#[inline]
pub fn check_mouse_time() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let sender = SENDER.lock().unwrap();
        allow_err!(sender.send(ipc::Data::MouseMoveTime(0)));
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_connect_status() -> UiStatus {
    UI_STATUS.lock().unwrap().clone()
}

#[inline]
pub fn temporary_password() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return password_security::temporary_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return TEMPORARY_PASSWD.lock().unwrap().clone();
}

#[inline]
pub fn update_temporary_password() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    password_security::update_temporary_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    allow_err!(ipc::update_temporary_password());
}

#[inline]
pub fn is_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let daemon_is_set = ipc::is_permanent_password_set();
        // `daemon_is_set` is authoritative for the return value. Local storage is only used to
        // decide whether we should attempt a sync to clear stale user-side state.
        let local_storage_is_empty = if daemon_is_set {
            true
        } else {
            let (storage, _) = Config::get_local_permanent_password_storage_and_salt();
            storage.is_empty()
        };
        if daemon_is_set || !local_storage_is_empty {
            allow_err!(ipc::sync_permanent_password_storage_from_daemon());
        }
        daemon_is_set
    }
}

#[inline]
pub fn is_local_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_local_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(ipc::sync_permanent_password_storage_from_daemon());
        Config::has_local_permanent_password()
    }
}

pub fn set_permanent_password_with_result(password: String) -> bool {
    if config::Config::is_disable_change_permanent_password() {
        return false;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        return config::Config::set_permanent_password(&password);
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        match crate::ipc::set_permanent_password_with_ack(password) {
            Ok(ok) => ok,
            Err(err) => {
                log::warn!("Failed to set permanent password via IPC: {err}");
                false
            }
        }
    }
}

#[inline]
pub fn get_peer(id: String) -> PeerConfig {
    PeerConfig::load(&id)
}

#[inline]
pub fn get_fav() -> Vec<String> {
    LocalConfig::get_fav()
}

#[inline]
pub fn store_fav(fav: Vec<String>) {
    LocalConfig::set_fav(fav);
}

#[inline]
pub fn is_process_trusted(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_process_trusted(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_can_screen_recording(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_screen_recording(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_installed_daemon(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_installed_daemon(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
#[cfg(feature = "flutter")]
pub fn is_can_input_monitoring(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_input_monitoring(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn get_error() -> String {
    #[cfg(not(any(feature = "cli")))]
    #[cfg(target_os = "linux")]
    {
        let dtype = crate::platform::linux::get_display_server();
        if crate::platform::linux::DISPLAY_SERVER_WAYLAND == dtype {
            return crate::server::wayland::common_get_error();
        }
        if dtype != crate::platform::linux::DISPLAY_SERVER_X11 {
            return format!(
                "{} {}, {}",
                crate::client::translate("Unsupported display server".to_owned()),
                dtype,
                crate::client::translate("x11 expected".to_owned()),
            );
        }
    }
    return "".to_owned();
}

#[inline]
pub fn is_login_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::is_login_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn current_is_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::current_is_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn get_new_version() -> String {
    (*SOFTWARE_UPDATE_URL
        .lock()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap_or(""))
    .to_string()
}

#[inline]
pub fn get_version() -> String {
    crate::VERSION.to_owned()
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_app_name() -> String {
    crate::get_app_name()
}

#[cfg(windows)]
#[inline]
pub fn create_shortcut(_id: String) {
    crate::platform::windows::create_shortcut(&_id).ok();
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn discover() {
    std::thread::spawn(move || {
        allow_err!(crate::lan::discover());
    });
}

#[cfg(feature = "flutter")]
pub fn peer_to_map(id: String, p: PeerConfig) -> HashMap<&'static str, String> {
    use hbb_common::sodiumoxide::base64;
    let hash = if crate::client::peer_config_has_explicit_password(&p) {
        base64::encode(&p.password, base64::Variant::Original)
    } else {
        String::new()
    };
    HashMap::<&str, String>::from_iter([
        ("id", id),
        ("username", p.info.username.clone()),
        ("hostname", p.info.hostname.clone()),
        ("platform", p.info.platform.clone()),
        (
            "alias",
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ),
        ("hash", hash),
    ])
}

#[cfg(feature = "flutter")]
pub fn peer_exists(id: &str) -> bool {
    PeerConfig::exists(id)
}

#[inline]
pub fn get_lan_peers() -> Vec<HashMap<&'static str, String>> {
    config::LanPeers::load()
        .peers
        .iter()
        .map(|peer| {
            HashMap::<&str, String>::from_iter([
                ("id", peer.id.clone()),
                ("username", peer.username.clone()),
                ("hostname", peer.hostname.clone()),
                ("platform", peer.platform.clone()),
            ])
        })
        .collect()
}

#[inline]
pub fn remove_discovered(id: String) {
    let mut peers = config::LanPeers::load().peers;
    peers.retain(|x| x.id != id);
    config::LanPeers::store(&peers);
}

#[inline]
pub fn get_uuid() -> String {
    crate::encode64(hbb_common::get_uuid())
}

#[inline]
pub fn get_init_async_job_status() -> String {
    INIT_ASYNC_JOB_STATUS.to_string()
}

#[inline]
pub fn reset_async_job_status() {
    *ASYNC_JOB_STATUS.lock().unwrap() = get_init_async_job_status();
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn change_id(id: String) {
    reset_async_job_status();
    let old_id = get_id();
    std::thread::spawn(move || {
        change_id_shared(id, old_id);
    });
}

#[inline]
pub fn http_request(url: String, method: String, body: Option<String>, header: String) {
    if !generic_http_headers_are_allowed(&header) {
        ASYNC_HTTP_STATUS
            .lock()
            .unwrap()
            .insert(url, "通用 HTTP 桥拒绝敏感或非法请求头".to_owned());
        return;
    }
    // Respond to concurrent requests for resources
    let current_request = ASYNC_HTTP_STATUS.clone();
    current_request
        .lock()
        .unwrap()
        .insert(url.clone(), " ".to_owned());
    std::thread::spawn(move || {
        let res = match crate::http_request_sync(url.clone(), method, body, header) {
            Err(err) => {
                log::error!("{}", err);
                err.to_string()
            }
            Ok(text) => text,
        };
        current_request.lock().unwrap().insert(url, res);
    });
}

#[inline]
pub fn sciter_http_request(url: String, method: String, body: Option<String>, header: String) {
    if !sciter_generic_headers_are_allowed(&header) {
        ASYNC_HTTP_STATUS
            .lock()
            .unwrap()
            .insert(url, "Sciter 通用 HTTP 桥拒绝裸请求头".to_owned());
        return;
    }
    http_request(url, method, body, header);
}

#[inline]
pub fn get_async_http_status(url: String) -> Option<String> {
    match ASYNC_HTTP_STATUS.lock().unwrap().get(&url) {
        None => None,
        Some(_str) => Some(_str.to_string()),
    }
}

#[inline]
#[cfg(not(feature = "flutter"))]
pub fn post_request(url: String, body: String, header: String) {
    *ASYNC_JOB_STATUS.lock().unwrap() = " ".to_owned();
    if !sciter_generic_headers_are_allowed(&header) {
        *ASYNC_JOB_STATUS.lock().unwrap() = "Sciter 通用 HTTP 桥拒绝裸请求头".to_owned();
        return;
    }
    std::thread::spawn(move || {
        *ASYNC_JOB_STATUS.lock().unwrap() = match crate::post_request_sync(url, body, &header) {
            Err(err) => err.to_string(),
            Ok(text) => text,
        };
    });
}

#[inline]
pub fn get_async_job_status() -> String {
    ASYNC_JOB_STATUS.lock().unwrap().clone()
}

#[inline]
pub fn get_langs() -> String {
    use serde_json::json;
    let mut x: Vec<(&str, String)> = crate::lang::LANGS
        .iter()
        .map(|a| (a.0, format!("{} ({})", a.1, a.0)))
        .collect();
    x.sort_by(|a, b| a.0.cmp(b.0));
    json!(x).to_string()
}

#[inline]
pub fn video_save_directory(root: bool) -> String {
    let appname = crate::get_app_name();
    // ui process can show it correctly Once vidoe process created it.
    let try_create = |path: &std::path::Path| {
        if !path.exists() {
            std::fs::create_dir_all(path).ok();
        }
        if path.exists() {
            path.to_string_lossy().to_string()
        } else {
            "".to_string()
        }
    };

    if root {
        // Currently, only installed windows run as root
        #[cfg(windows)]
        {
            let drive = std::env::var("SystemDrive").unwrap_or("C:".to_owned());
            let dir =
                std::path::PathBuf::from(format!("{drive}\\ProgramData\\{appname}\\recording",));
            return dir.to_string_lossy().to_string();
        }
    }
    // Get directory from config file otherwise --server will use the old value from global var.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let dir = LocalConfig::get_option_from_file(OPTION_VIDEO_SAVE_DIRECTORY);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let dir = LocalConfig::get_option(OPTION_VIDEO_SAVE_DIRECTORY);
    if !dir.is_empty() {
        return dir;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if let Ok(home) = config::APP_HOME_DIR.read() {
        let mut path = home.to_owned();
        path.push_str(format!("/{appname}/ScreenRecord").as_str());
        let dir = try_create(&std::path::Path::new(&path));
        if !dir.is_empty() {
            return dir;
        }
    }

    if let Some(user) = directories_next::UserDirs::new() {
        if let Some(video_dir) = user.video_dir() {
            let dir = try_create(&video_dir.join(&appname));
            if !dir.is_empty() {
                return dir;
            }
            if video_dir.exists() {
                return video_dir.to_string_lossy().to_string();
            }
        }
        if let Some(desktop_dir) = user.desktop_dir() {
            if desktop_dir.exists() {
                return desktop_dir.to_string_lossy().to_string();
            }
        }
        let home = user.home_dir();
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    // same order as above
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(home) = crate::platform::get_active_user_home() {
        let name = if cfg!(target_os = "macos") {
            "Movies"
        } else {
            "Videos"
        };
        let video_dir = home.join(name);
        let dir = try_create(&video_dir.join(&appname));
        if !dir.is_empty() {
            return dir;
        }
        if video_dir.exists() {
            return video_dir.to_string_lossy().to_string();
        }
        let desktop_dir = home.join("Desktop");
        if desktop_dir.exists() {
            return desktop_dir.to_string_lossy().to_string();
        }
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dir = try_create(&parent.join("videos"));
            if !dir.is_empty() {
                return dir;
            }
            // basically exist
            return parent.to_string_lossy().to_string();
        }
    }
    Default::default()
}

#[inline]
pub fn get_api_server() -> String {
    crate::get_api_server(
        get_option("api-server"),
        get_option("custom-rendezvous-server"),
    )
}

pub enum DeployResult {
    Ok,
    NotEnabled,
    InvalidInput,
    IdTaken(String),
    Error(String),
}

impl DeployResult {
    pub fn message(&self) -> String {
        match self {
            Self::Ok => "".to_owned(),
            Self::NotEnabled => "The server does not require explicit deployment.".to_owned(),
            Self::InvalidInput => "Invalid input.".to_owned(),
            Self::IdTaken(id) => {
                format!(
                    "Id `{}` is already used by another machine on the server.",
                    id
                )
            }
            Self::Error(err) => err.clone(),
        }
    }
}

pub fn deploy_device(token: String, new_id: Option<String>) -> DeployResult {
    if Config::no_register_device() {
        return DeployResult::Error("Cannot deploy an unregistrable device!".to_owned());
    }
    let token = token.trim();
    if token.is_empty() {
        return DeployResult::Error("token is required!".to_owned());
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let local_id = Config::get_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let local_id = ipc::get_id();
    let id_to_deploy = new_id.clone().unwrap_or_else(|| local_id.clone());
    let uuid = crate::encode64(hbb_common::get_uuid());
    let pk = crate::encode64(Config::get_key_pair().1);
    let body = serde_json::json!({
        "id": id_to_deploy,
        "uuid": uuid,
        "pk": pk,
    });
    let url = get_api_server() + "/api/devices/deploy";
    let response = match crate::common::strict_http_request_one_shot_bearer_blocking(
        crate::common::StrictHttpRequest::new(crate::common::StrictHttpMethod::Post, url)
            .json_body(body.to_string()),
        token.to_owned(),
    ) {
        Ok(response) => response,
        Err(err) => return DeployResult::Error(format!("Request failed: {}", err)),
    };
    if !response.is_success() {
        return DeployResult::Error(format!("Request failed with status {}", response.status));
    }
    let text = response.body;
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    match parsed["result"].as_str().unwrap_or("") {
        "OK" => {
            if let Some(new_id) = new_id {
                if new_id != local_id {
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        Config::set_key_confirmed(false);
                        Config::set_id(&new_id);
                    }
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if let Err(err) = ipc::set_config("id", new_id) {
                        return DeployResult::Error(format!(
                            "Failed to persist deployed id locally: {}",
                            err
                        ));
                    }
                }
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            if let Err(err) = ipc::notify_deployed() {
                log::warn!("Failed to notify deployed state: {}", err);
            }
            #[cfg(target_os = "android")]
            {
                crate::rendezvous_mediator::NEEDS_DEPLOY
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                crate::rendezvous_mediator::reset_needs_deploy_notification();
                crate::rendezvous_mediator::RendezvousMediator::restart();
            }
            DeployResult::Ok
        }
        "NOT_ENABLED" => DeployResult::NotEnabled,
        "INVALID_INPUT" => DeployResult::InvalidInput,
        "ID_TAKEN" => DeployResult::IdTaken(id_to_deploy),
        _ => {
            if text.is_empty() {
                DeployResult::Error("Unknown response.".to_owned())
            } else {
                DeployResult::Error(text)
            }
        }
    }
}

#[inline]
pub fn has_hwcodec() -> bool {
    // Has real hardware codec using gpu
    (cfg!(feature = "hwcodec") && cfg!(not(target_os = "ios"))) || cfg!(feature = "mediacodec")
}

#[inline]
pub fn has_vram() -> bool {
    cfg!(feature = "vram")
}

#[cfg(feature = "flutter")]
#[inline]
pub fn supported_hwdecodings() -> (bool, bool) {
    let decoding =
        scrap::codec::Decoder::supported_decodings(None, use_texture_render(), None, &vec![]);
    #[allow(unused_mut)]
    let (mut h264, mut h265) = (decoding.ability_h264 > 0, decoding.ability_h265 > 0);
    #[cfg(feature = "vram")]
    {
        // supported_decodings check runtime luid
        let vram = scrap::vram::VRamDecoder::possible_available_without_check();
        if vram.0 {
            h264 = true;
        }
        if vram.1 {
            h265 = true;
        }
    }
    (h264, h265)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_root() -> bool {
    crate::platform::is_root()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_root() -> bool {
    false
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn check_super_user_permission() -> bool {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return crate::platform::check_super_user_permission().unwrap_or(false);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return true;
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn check_zombie() {
    let mut deads = Vec::new();
    loop {
        let mut lock = CHILDREN.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                unregister_spawned_audit_launch(c.id());
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            unregister_spawned_audit_launch(c.id());
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                unregister_spawned_audit_launch(c.id());
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    let launch_nonce = new_audit_launch_nonce();
    let mut args = vec![
        format!("--{}", remote_type),
        id.clone(),
        String::new(), // password占位，后续内部参数不得被旧解析器当作密码。
    ];
    if force_relay {
        args.push("--relay".to_string());
    }
    args.push(format!("--audit-capability-launch={launch_nonce}"));
    match crate::run_me(args) {
        Ok(child) => {
            let child_pid = child.id();
            let conn_type = match remote_type.as_str() {
                "file-transfer" => 1,
                "port-forward" | "rdp" => 2,
                "view-camera" => 3,
                "terminal" => 4,
                _ => 0,
            };
            if let Err(error) =
                register_spawned_audit_launch(launch_nonce, child_pid, id.clone(), conn_type)
            {
                log::warn!("无法登记远程进程的审计能力: {error}");
            }
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

// Make sure `SENDER` is inited here.
#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn start_option_status_sync() {
    let _sender = SENDER.lock().unwrap();
}

// not call directly
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn check_connect_status(reconnect: bool) -> mpsc::UnboundedSender<ipc::Data> {
    let (tx, rx) = mpsc::unbounded_channel::<ipc::Data>();
    std::thread::spawn(move || check_connect_status_(reconnect, rx));
    tx
}

#[cfg(feature = "flutter")]
pub fn begin_account_auth_attempt() -> ResultType<crate::hbbs_http::auth_binding::AuthAttempt> {
    let _publish_guard = lock_server_config_publish()?;
    account::OidcSession::begin_external_auth_attempt(get_api_server())
}

#[cfg(feature = "flutter")]
pub fn account_auth(
    op: String,
    id: String,
    uuid: String,
    remember_me: bool,
) -> ResultType<crate::hbbs_http::auth_binding::AuthAttempt> {
    let _publish_guard = lock_server_config_publish()?;
    account::OidcSession::account_auth(get_api_server(), op, id, uuid, remember_me)
}

#[cfg(feature = "flutter")]
pub fn set_user_default_option(key: String, value: String) {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().set(key, value);
}

#[cfg(feature = "flutter")]
pub fn get_user_default_option(key: String) -> String {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().get(&key)
}

pub fn get_fingerprint() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if Config::get_key_confirmed() {
        return crate::common::pk_to_fingerprint(Config::get_key_pair().1);
    } else {
        return "".to_owned();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_fingerprint();
}

#[inline]
pub fn get_login_device_info() -> LoginDeviceInfo {
    LoginDeviceInfo {
        // std::env::consts::OS is better than whoami::platform() here.
        os: std::env::consts::OS.to_owned(),
        r#type: "client".to_owned(),
        name: crate::common::hostname(),
    }
}

#[inline]
pub fn get_login_device_info_json() -> String {
    serde_json::to_string(&get_login_device_info()).unwrap_or("{}".to_string())
}

// notice: avoiding create ipc connection repeatedly,
// because windows named pipe has serious memory leak issue.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn check_connect_status_(reconnect: bool, rx: mpsc::UnboundedReceiver<ipc::Data>) {
    #[cfg(not(feature = "flutter"))]
    let mut key_confirmed = false;
    let mut rx = rx;
    let mut mouse_time = 0;
    #[cfg(feature = "flutter")]
    let mut video_conn_count = 0;
    #[cfg(not(feature = "flutter"))]
    let mut id = "".to_owned();
    let is_cm = crate::common::is_cm();

    loop {
        if let Ok(mut c) = ipc::connect(1000, "").await {
            let mut timer = crate::rustdesk_interval(time::interval(time::Duration::from_secs(1)));
            loop {
                tokio::select! {
                    res = c.next() => {
                        match res {
                            Err(err) => {
                                log::error!("ipc connection closed: {}", err);
                                if is_cm {
                                    crate::ui_cm_interface::quit_cm();
                                }
                                break;
                            }
                            #[cfg(not(any(target_os = "android", target_os = "ios")))]
                            Ok(Some(ipc::Data::MouseMoveTime(v))) => {
                                mouse_time = v;
                                UI_STATUS.lock().unwrap().mouse_time = v;
                            }
                            Ok(Some(ipc::Data::Options(Some(v)))) => {
                                match accept_authoritative_options(v) {
                                    Ok(()) => {
                                        *OPTION_SYNCED.lock().unwrap() = true;
                                    }
                                    Err(error) => {
                                        log::error!(
                                            "拒绝发布未经认证协调的权威 Options 快照: {error}"
                                        );
                                    }
                                }
                            }
                            Ok(Some(ipc::Data::Config((name, Some(value))))) => {
                                if name == "id" {
                                    #[cfg(not(feature = "flutter"))]
                                    {
                                        id = value;
                                    }
                                } else if name == "temporary-password" {
                                    *TEMPORARY_PASSWD.lock().unwrap() = value;
                                }
                            }
                            #[cfg(feature = "flutter")]
                            Ok(Some(ipc::Data::VideoConnCount(Some(n)))) => {
                                video_conn_count = n;
                            }
                            Ok(Some(ipc::Data::OnlineStatus(Some((mut x, _c))))) => {
                                if x > 0 {
                                    x = 1
                                }
                                #[cfg(not(feature = "flutter"))]
                                {
                                    key_confirmed = _c;
                                }
                                *UI_STATUS.lock().unwrap() = UiStatus {
                                    status_num: x as _,
                                    #[cfg(not(feature = "flutter"))]
                                    key_confirmed: _c,
                                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                                    mouse_time,
                                    #[cfg(not(feature = "flutter"))]
                                    id: id.clone(),
                                    #[cfg(feature = "flutter")]
                                    video_conn_count,
                                };
                            }
                            Ok(Some(ipc::Data::ControlPermissionsRemoteModify(v))) => {
                                *IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS.lock().unwrap() = v;
                            }
                            #[cfg(target_os = "windows")]
                            Ok(Some(ipc::Data::FileTransferEnabledState(v))) => {
                                if let Some(enabled) = v {
                                    let mut lock = IS_FILE_TRANSFER_ENABLED.lock().unwrap();
                                    if *lock != v {
                                        clipboard::ContextSend::enable(enabled);
                                        *lock = v;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(data) = rx.recv() => {
                        allow_err!(c.send(&data).await);
                    }
                    _ = timer.tick() => {
                        c.send(&ipc::Data::OnlineStatus(None)).await.ok();
                        c.send(&ipc::Data::Options(None)).await.ok();
                        c.send(&ipc::Data::Config(("id".to_owned(), None))).await.ok();
                        c.send(&ipc::Data::Config(("temporary-password".to_owned(), None))).await.ok();
                        #[cfg(feature = "flutter")]
                        c.send(&ipc::Data::VideoConnCount(None)).await.ok();
                        c.send(&ipc::Data::ControlPermissionsRemoteModify(None)).await.ok();
                        #[cfg(target_os = "windows")]
                        c.send(&ipc::Data::FileTransferEnabledState(None)).await.ok();
                    }
                }
            }
        }
        if !reconnect {
            OPTIONS
                .lock()
                .unwrap()
                .insert("ipc-closed".to_owned(), "Y".to_owned());
            break;
        }
        *UI_STATUS.lock().unwrap() = UiStatus {
            status_num: -1,
            #[cfg(not(feature = "flutter"))]
            key_confirmed,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            mouse_time,
            #[cfg(not(feature = "flutter"))]
            id: id.clone(),
            #[cfg(feature = "flutter")]
            video_conn_count,
        };
        sleep(1.).await;
    }
}

#[allow(dead_code)]
pub fn option_synced() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        OPTION_SYNCED.lock().unwrap().clone()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        true
    }
}

#[cfg(any(target_os = "android", feature = "flutter"))]
#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub(crate) async fn send_to_cm(data: &ipc::Data) {
    if let Ok(mut c) = ipc::connect(1000, "_cm").await {
        c.send(data).await.ok();
    }
}

const INVALID_FORMAT: &'static str = "Invalid format";
const UNKNOWN_ERROR: &'static str = "Unknown error";

#[inline]
#[tokio::main(flavor = "current_thread")]
pub async fn change_id_shared(id: String, old_id: String) -> String {
    let res = change_id_shared_(id, old_id).await.to_owned();
    *ASYNC_JOB_STATUS.lock().unwrap() = res.clone();
    res
}

pub async fn change_id_shared_(id: String, old_id: String) -> &'static str {
    if !hbb_common::is_valid_custom_id(&id) {
        log::debug!(
            "debugging invalid id: \"{id}\", len: {}, base64: \"{}\"",
            id.len(),
            crate::encode64(&id)
        );
        let bom = id.trim_start_matches('\u{FEFF}');
        log::debug!("bom: {}", hbb_common::is_valid_custom_id(&bom));
        return INVALID_FORMAT;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let uuid = Bytes::from(
        hbb_common::machine_uid::get()
            .unwrap_or("".to_owned())
            .as_bytes()
            .to_vec(),
    );
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let uuid = Bytes::from(hbb_common::get_uuid());

    if uuid.is_empty() {
        log::error!("Failed to change id, uuid is_empty");
        return UNKNOWN_ERROR;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let rendezvous_servers = crate::ipc::get_rendezvous_servers(1_000).await;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let rendezvous_servers = Config::get_rendezvous_servers();

    let mut futs = Vec::new();
    let err: Arc<Mutex<&str>> = Default::default();
    for rendezvous_server in rendezvous_servers {
        let err = err.clone();
        let id = id.to_owned();
        let uuid = uuid.clone();
        let old_id = old_id.clone();
        futs.push(tokio::spawn(async move {
            let tmp = check_id(rendezvous_server, old_id, id, uuid).await;
            if !tmp.is_empty() {
                *err.lock().unwrap() = tmp;
            }
        }));
    }
    join_all(futs).await;
    let err = *err.lock().unwrap();
    if err.is_empty() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        crate::ipc::set_config_async("id", id.to_owned()).await.ok();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            Config::set_key_confirmed(false);
            Config::set_id(&id);
        }
    }
    err
}

async fn check_id(
    rendezvous_server: String,
    old_id: String,
    id: String,
    uuid: Bytes,
) -> &'static str {
    if let Ok(mut socket) = hbb_common::socket_client::connect_tcp(
        crate::check_port(rendezvous_server, RENDEZVOUS_PORT),
        CONNECT_TIMEOUT,
    )
    .await
    {
        let mut msg_out = Message::new();
        msg_out.set_register_pk(RegisterPk {
            old_id,
            id,
            uuid,
            ..Default::default()
        });
        let mut ok = false;
        if socket.send(&msg_out).await.is_ok() {
            if let Some(msg_in) =
                crate::common::get_next_nonkeyexchange_msg(&mut socket, None).await
            {
                match msg_in.union {
                    Some(rendezvous_message::Union::RegisterPkResponse(rpr)) => {
                        match rpr.result.enum_value() {
                            Ok(register_pk_response::Result::OK) => {
                                ok = true;
                            }
                            Ok(register_pk_response::Result::ID_EXISTS) => {
                                return "Not available";
                            }
                            Ok(register_pk_response::Result::TOO_FREQUENT) => {
                                return "Too frequent";
                            }
                            Ok(register_pk_response::Result::NOT_SUPPORT) => {
                                return "server_not_support";
                            }
                            Ok(register_pk_response::Result::SERVER_ERROR) => {
                                return "Server error";
                            }
                            Ok(register_pk_response::Result::INVALID_ID_FORMAT) => {
                                return INVALID_FORMAT;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        if !ok {
            return UNKNOWN_ERROR;
        }
    } else {
        return "Failed to connect to rendezvous server";
    }
    ""
}

// if it's relay id, return id processed, otherwise return original id
pub fn handle_relay_id(id: &str) -> &str {
    if id.ends_with(r"\r") || id.ends_with(r"/r") {
        &id[0..id.len() - 2]
    } else {
        id
    }
}

pub fn support_remove_wallpaper() -> bool {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    return crate::platform::WallPaperRemover::support();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    return false;
}

pub fn has_valid_2fa() -> bool {
    let raw = get_option("2fa");
    crate::auth_2fa::get_2fa(Some(raw)).is_some()
}

pub fn generate2fa() -> String {
    crate::auth_2fa::generate2fa()
}

pub fn verify2fa(code: String) -> bool {
    let res = crate::auth_2fa::verify2fa(code);
    if res {
        refresh_options();
    }
    res
}

pub fn has_valid_bot() -> bool {
    crate::auth_2fa::TelegramBot::get().map_or(false, |bot| bot.is_some())
}

pub fn verify_bot(token: String) -> String {
    match crate::auth_2fa::get_chatid_telegram(&token) {
        Err(err) => err.to_string(),
        Ok(None) => {
            "To activate the bot, simply send a message beginning with a forward slash (\"/\") like \"/hello\" to its chat.".to_owned()
        }
        _ => "".to_owned(),
    }
}

pub fn check_hwcodec() {
    #[cfg(feature = "hwcodec")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        use std::sync::Once;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| {
            if crate::platform::is_installed() {
                ipc::notify_server_to_check_hwcodec().ok();
                ipc::client_get_hwcodec_config_thread(3);
            } else {
                scrap::hwcodec::start_check_process();
            }
        })
    }
}

#[cfg(feature = "flutter")]
pub fn get_unlock_pin() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return String::default();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_unlock_pin();
}

#[cfg(feature = "flutter")]
pub fn set_unlock_pin(pin: String) -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return String::default();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    match ipc::set_unlock_pin(pin, true) {
        Ok(_) => String::default(),
        Err(err) => err.to_string(),
    }
}

#[cfg(feature = "flutter")]
pub fn get_trusted_devices() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_trusted_devices_json();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_trusted_devices();
}

#[cfg(feature = "flutter")]
pub fn remove_trusted_devices(json: &str) {
    let hwids = serde_json::from_str::<Vec<Bytes>>(json).unwrap_or_default();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::remove_trusted_devices(&hwids);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::remove_trusted_devices(hwids);
}

#[cfg(feature = "flutter")]
pub fn clear_trusted_devices() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::clear_trusted_devices();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::clear_trusted_devices();
}

#[cfg(feature = "flutter")]
pub fn max_encrypt_len() -> usize {
    hbb_common::config::ENCRYPT_MAX_LEN
}

pub fn is_remote_modify_enabled_by_control_permissions() -> Option<bool> {
    *IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS
        .lock()
        .unwrap()
}
