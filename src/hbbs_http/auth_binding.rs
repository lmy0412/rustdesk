use super::auth_state_store::{
    checked_increment, cursor_key, random_nonce, subject_sha256, token_sha256, AuthAttemptRecord,
    AuthNamespaceState, AuthStateStore, AuthTombstone, NativeAuthSession, NativeAuthStateV1,
    PendingLogout, MAX_PENDING_LOGOUTS, MAX_SAFE_INTEGER,
};
pub use super::auth_state_store::{
    AddressBookCapability, AuthAuthorityAnchor, AuthSafeUser, AuthSubject,
};
use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    config::LocalConfig,
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(test, feature = "flutter"))]
use std::collections::HashSet;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
    sync::{Mutex, OnceLock},
};
use url::{Host, Url};

const MAX_JWT_SUBJECT_BYTES: usize = 512;

static MAIN_UI_AUTH: OnceLock<Mutex<AuthBinding>> = OnceLock::new();
static TRUSTED_PROCESS_ROLE: OnceLock<TrustedProcessRole> = OnceLock::new();
#[cfg(any(test, feature = "flutter"))]
static AUTH_ATTEMPTS_IN_FLIGHT: OnceLock<Mutex<HashSet<AuthAttempt>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedProcessRole {
    MainUi,
    NonUi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalHashSource {
    LegacyPersonal,
    CommercialPersonal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PersonalHashAllowlist {
    normalized_api_base: String,
    namespace: String,
    session_epoch: u64,
    session_nonce: String,
    generation_nonce: String,
    source: PersonalHashSource,
    hashes: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PersonalHashConnectionCapability {
    normalized_api_base: String,
    namespace: String,
    cursor_key: String,
    auth_epoch: u64,
    logout_generation: u64,
    session_epoch: u64,
    session_nonce: String,
    fence: u64,
    generation_nonce: String,
    source: PersonalHashSource,
    peer_id: String,
    hash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PersonalHashReceipt {
    receipt_id: String,
    handle: CredentialedRequestHandle,
    fence: u64,
    source: PersonalHashSource,
    hashes: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommercialPersonalHashAccumulator {
    handle: CredentialedRequestHandle,
    fence: u64,
    guid: String,
    total: usize,
    page_size: usize,
    next_page: usize,
    received: usize,
    seen_ids: BTreeSet<String>,
    hashes: BTreeMap<String, Vec<u8>>,
}

impl PersonalHashAllowlist {
    fn matches_session(&self, session: &NativeAuthSession) -> bool {
        self.normalized_api_base == session.normalized_api_base
            && self.namespace == session.subject.namespace_component()
            && self.session_epoch == session.epoch
            && self.session_nonce == session.nonce
    }
}

fn classify_process_role_from_args<'a>(
    args: impl IntoIterator<Item = &'a str>,
) -> TrustedProcessRole {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = args;
        return TrustedProcessRole::MainUi;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut has_disallowed_argument = false;
        for argument in args.into_iter().skip(1) {
            let command = argument.split('=').next().unwrap_or(argument);
            if matches!(
                command,
                "multi_window"
                    | "--cm"
                    | "--cm-no-ui"
                    | "--service"
                    | "--server"
                    | "--tray"
                    | "--install"
                    | "--uninstall"
                    | "--update"
                    | "--connect"
                    | "--play"
                    | "--file-transfer"
                    | "--view-camera"
                    | "--port-forward"
                    | "--terminal"
                    | "--rdp"
                    | "--password"
                    | "--set-unlock-pin"
                    | "--get-id"
                    | "--set-id"
                    | "--config"
                    | "--option"
                    | "--assign"
                    | "--deploy"
            ) || command.starts_with("--portable-service")
            {
                has_disallowed_argument = true;
                break;
            }
        }
        if has_disallowed_argument {
            TrustedProcessRole::NonUi
        } else {
            TrustedProcessRole::MainUi
        }
    }
}

/// 必须由桌面原生入口在加载可变配置前调用；后续 Dart 字符串不能改变该角色。
pub fn freeze_current_process_role() -> TrustedProcessRole {
    *TRUSTED_PROCESS_ROLE.get_or_init(|| {
        let args = std::env::args().collect::<Vec<_>>();
        classify_process_role_from_args(args.iter().map(String::as_str))
    })
}

pub fn require_trusted_main_ui_process() -> ResultType<()> {
    if freeze_current_process_role() != TrustedProcessRole::MainUi {
        bail!("当前原生进程角色不得访问主界面认证权威");
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct AuthAttempt {
    pub attempt_id: u64,
    pub nonce: String,
    pub normalized_api_base: String,
    pub logout_generation: u64,
}

impl std::fmt::Debug for AuthAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthAttempt")
            .field("attempt_id", &self.attempt_id)
            .field("nonce", &"<redacted>")
            .field("normalized_api_base", &"<redacted>")
            .field("logout_generation", &self.logout_generation)
            .finish()
    }
}

/// 同一 exact attempt 的 strict login 网络提交只能有一个 owner；guard 不持有认证锁。
#[cfg(any(test, feature = "flutter"))]
pub(crate) struct AuthAttemptInFlightClaim {
    attempt: AuthAttempt,
}

#[cfg(any(test, feature = "flutter"))]
impl Drop for AuthAttemptInFlightClaim {
    fn drop(&mut self) {
        let claims = AUTH_ATTEMPTS_IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()));
        if let Ok(mut claims) = claims.lock() {
            claims.remove(&self.attempt);
        }
    }
}

/// claim 锁只覆盖 HashSet CAS；sender 运行时不持有任何全局互斥锁。
#[cfg(any(test, feature = "flutter"))]
pub(crate) fn claim_auth_attempt_and_send<T>(
    attempt: &AuthAttempt,
    attempt_is_current: impl FnOnce(&AuthAttempt) -> bool,
    sender: impl FnOnce() -> T,
) -> ResultType<(AuthAttemptInFlightClaim, Option<T>)> {
    let claims = AUTH_ATTEMPTS_IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()));
    {
        // 不同 attempt 只在 contains/insert 的极短临界区串行，不能因全局注册表瞬时竞争
        // 被误判为重复提交；同一 exact attempt 仍保持非排队、立即失败。
        let mut claims = claims
            .lock()
            .map_err(|_| anyhow!("登录请求提交门禁不可用"))?;
        if !claims.insert(attempt.clone()) {
            bail!("同一登录请求正在处理中");
        }
    }
    let claim = AuthAttemptInFlightClaim {
        attempt: attempt.clone(),
    };
    let output = attempt_is_current(attempt).then(sender);
    Ok((claim, output))
}

/// AuthAttempt 只以原生侧生成的规范 JSON 字符串跨 FFI；Dart 不解析或重建它。
pub fn serialize_auth_attempt(attempt: &AuthAttempt) -> ResultType<String> {
    serde_json::to_string(attempt).map_err(|_| anyhow!("无法序列化原生登录请求能力"))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentitySnapshot {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub uuid: String,
}

impl std::fmt::Debug for DeviceIdentitySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceIdentitySnapshot")
            .field("id", &self.id)
            .field("uuid", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSessionSnapshot {
    pub normalized_api_base: String,
    pub namespace: String,
    pub subject: AuthSubject,
    pub cursor_key: String,
    pub cursor: u64,
    pub capability: AddressBookCapability,
    pub force_full_pending: bool,
    pub is_pro: bool,
    pub session_epoch: u64,
    pub session_nonce: String,
    pub safe_user: AuthSafeUser,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSnapshot {
    pub revision: u64,
    pub auth_epoch: u64,
    pub logout_generation: u64,
    pub pending_logout_count: usize,
    #[serde(default)]
    pub session: Option<AuthSessionSnapshot>,
    pub corrupt: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectiveApiBaseTransition {
    pub base_changed: bool,
    pub session_invalidated: bool,
    pub snapshot: AuthSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialedRequestHandle {
    pub request_context_id: String,
    pub normalized_api_base: String,
    pub namespace: String,
    pub session_epoch: u64,
    pub session_nonce: String,
    pub cursor_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrustedAddressBookReset {
    normalized_api_base: String,
    namespace: String,
    session_epoch: u64,
    session_nonce: String,
    cursor_key: String,
    expected_cursor: u64,
    target_cursor: u64,
}

impl TrustedAddressBookReset {
    fn new(handle: &CredentialedRequestHandle, expected_cursor: u64, target_cursor: u64) -> Self {
        Self {
            normalized_api_base: handle.normalized_api_base.clone(),
            namespace: handle.namespace.clone(),
            session_epoch: handle.session_epoch,
            session_nonce: handle.session_nonce.clone(),
            cursor_key: handle.cursor_key.clone(),
            expected_cursor,
            target_cursor,
        }
    }

    fn matches(
        &self,
        handle: &CredentialedRequestHandle,
        expected_cursor: u64,
        target_cursor: u64,
    ) -> bool {
        self.normalized_api_base == handle.normalized_api_base
            && self.namespace == handle.namespace
            && self.session_epoch == handle.session_epoch
            && self.session_nonce == handle.session_nonce
            && self.cursor_key == handle.cursor_key
            && self.expected_cursor == expected_cursor
            && self.target_cursor == target_cursor
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLogoutTicket {
    pub ticket_id: String,
    pub normalized_api_base: String,
    pub logout_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PendingLogoutOutcome {
    Revoked,
    UnsupportedLocalOnly,
    Retained {
        #[serde(default)]
        status: Option<u16>,
        retry_after_unix_ms: u64,
    },
    Missing,
}

#[derive(Clone)]
pub(crate) struct CredentialedRequestContext {
    pub handle: CredentialedRequestHandle,
    pub access_token: String,
}

impl std::fmt::Debug for CredentialedRequestContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialedRequestContext")
            .field("handle", &self.handle)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PendingLogoutRequest {
    pub ticket: PendingLogoutTicket,
    pub access_token: String,
    pub device_identity: DeviceIdentitySnapshot,
    pub attempt_count: u32,
    pub retry_after_unix_ms: u64,
}

impl std::fmt::Debug for PendingLogoutRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingLogoutRequest")
            .field("ticket", &self.ticket)
            .field("access_token", &"<redacted>")
            .field("device_identity", &self.device_identity)
            .field("attempt_count", &self.attempt_count)
            .field("retry_after_unix_ms", &self.retry_after_unix_ms)
            .finish()
    }
}

pub struct AuthBinding {
    store: AuthStateStore,
    // Flutter 登录只有在 exact UI owner ACK 后才能签发 credentialed handle。
    // 该门禁只存在于主 UI 进程；重启加载的既有 durable session 视为已接纳。
    pending_ui_acceptance: Option<CredentialedRequestHandle>,
    // reset 授权只来自本进程已认证的 worker 响应。它不落盘；重启后必须重新探测，
    // 避免旧授权跨进程或跨代复用。
    trusted_address_book_reset: Option<TrustedAddressBookReset>,
    // personal hash 只保留本进程当前认证代，绝不写磁盘或从通用地址簿缓存恢复。
    personal_hash_allowlist: Option<PersonalHashAllowlist>,
    personal_hash_receipt: Option<PersonalHashReceipt>,
    commercial_personal_guid: Option<(CredentialedRequestHandle, String)>,
    commercial_personal_hash_accumulator: Option<CommercialPersonalHashAccumulator>,
    // 每个 personal 读取请求必须绑定“请求开始时”的栅栏；任何写入开始/结束或
    // 来源失效都会推进栅栏，使迟到的旧响应无法重新发布已删除的 hash。
    personal_hash_fence: u64,
    personal_hash_mutations_in_flight: u64,
}

impl AuthBinding {
    fn clear_active_personal_hash_material(&mut self) {
        self.personal_hash_allowlist = None;
        self.personal_hash_receipt = None;
        self.commercial_personal_hash_accumulator = None;
    }

    fn advance_personal_hash_fence(&mut self) -> ResultType<u64> {
        self.personal_hash_fence =
            checked_increment(self.personal_hash_fence, "personal hash fence")?;
        Ok(self.personal_hash_fence)
    }

    fn clear_personal_hash_state(&mut self) -> ResultType<()> {
        self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        self.commercial_personal_guid = None;
        // 仅用于认证会话已经换代或失效的生命周期边界；旧 handle 的 finish 会被拒绝。
        self.personal_hash_mutations_in_flight = 0;
        Ok(())
    }

    fn invalidate_personal_hash_state_in_current_session(&mut self) -> ResultType<()> {
        self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        self.commercial_personal_guid = None;
        // 同一 session 的 capability/cursor 变更不得破坏 begin/finish 配对。
        Ok(())
    }

    pub fn open(anchor: AuthAuthorityAnchor) -> ResultType<Self> {
        Ok(Self {
            store: AuthStateStore::open(anchor)?,
            pending_ui_acceptance: None,
            trusted_address_book_reset: None,
            personal_hash_allowlist: None,
            personal_hash_receipt: None,
            commercial_personal_guid: None,
            commercial_personal_hash_accumulator: None,
            personal_hash_fence: 0,
            personal_hash_mutations_in_flight: 0,
        })
    }

    pub fn reset_corrupt(anchor: AuthAuthorityAnchor) -> ResultType<Self> {
        scrub_legacy_auth_mirror();
        Ok(Self {
            store: AuthStateStore::reset_corrupt(anchor)?,
            pending_ui_acceptance: None,
            trusted_address_book_reset: None,
            personal_hash_allowlist: None,
            personal_hash_receipt: None,
            commercial_personal_guid: None,
            commercial_personal_hash_accumulator: None,
            personal_hash_fence: 0,
            personal_hash_mutations_in_flight: 0,
        })
    }

    pub fn authority_directory(&self) -> &Path {
        self.store.directory()
    }

    pub fn snapshot(&self) -> AuthSnapshot {
        let state = self.store.snapshot();
        let mut snapshot = snapshot_from_state(&state);
        if self
            .pending_ui_acceptance
            .as_ref()
            .is_some_and(|pending| state_handle_is_current(&state, pending))
        {
            snapshot.session = None;
        }
        snapshot
    }

    pub fn begin_auth_attempt(&mut self, api_base: &str) -> ResultType<AuthAttempt> {
        let normalized_api_base = normalize_api_base(api_base)?;
        validate_strict_target(&normalized_api_base)?;
        let state = self.store.update(|state| {
            if state
                .session
                .as_ref()
                .is_some_and(|session| session.normalized_api_base != normalized_api_base)
            {
                bail!("Active auth session must be logged out before changing the API base");
            }
            if state.pending_logouts.len() >= MAX_PENDING_LOGOUTS {
                bail!("Pending logout queue is full");
            }
            if state
                .pending_logouts
                .iter()
                .any(|pending| pending.normalized_api_base == normalized_api_base)
            {
                bail!("Authentication is fenced until the pending logout completes");
            }
            state.attempt_counter = checked_increment(state.attempt_counter, "attempt counter")?;
            state.latest_attempt = Some(AuthAttemptRecord {
                attempt_id: state.attempt_counter,
                nonce: random_nonce(),
                normalized_api_base: normalized_api_base.clone(),
                logout_generation: state.logout_generation,
            });
            Ok(())
        })?;
        let attempt = state
            .latest_attempt
            .ok_or_else(|| anyhow!("Native auth attempt was not persisted"))?;
        Ok(AuthAttempt {
            attempt_id: attempt.attempt_id,
            nonce: attempt.nonce,
            normalized_api_base: attempt.normalized_api_base,
            logout_generation: attempt.logout_generation,
        })
    }

    pub fn commit_auth_attempt(
        &mut self,
        attempt: &AuthAttempt,
        access_token: String,
        mut safe_user: AuthSafeUser,
        expires_at: Option<i64>,
    ) -> ResultType<AuthSnapshot> {
        if access_token.is_empty() {
            bail!("Authentication response did not contain an access token");
        }
        let subject = select_subject(&safe_user, &access_token)?;
        // verifier 只用于本次响应校验，不属于可持久化的安全用户摘要。
        safe_user.verifier.clear();
        // 先校验内存 personal fence 仍可推进，确保 durable commit 后不再出现失败分支。
        let next_personal_hash_fence =
            checked_increment(self.personal_hash_fence, "personal hash fence")?;
        let namespace_key = cursor_key(&attempt.normalized_api_base, &subject);
        let token_fingerprint = token_sha256(&access_token);
        let state = self.store.update(|state| {
            ensure_attempt_is_current(state, attempt)?;
            if state.pending_logouts.len() >= MAX_PENDING_LOGOUTS {
                bail!("Pending logout queue is full");
            }
            state.auth_epoch = checked_increment(state.auth_epoch, "epoch")?;
            let epoch = state.auth_epoch;
            let session_nonce = random_nonce();
            let namespace = state.namespaces.entry(namespace_key.clone()).or_default();
            namespace.capability = AddressBookCapability::Unknown;
            namespace.force_full_pending = true;
            namespace.pro_epoch = None;
            state.session = Some(NativeAuthSession {
                access_token: access_token.clone(),
                token_sha256: token_fingerprint.clone(),
                normalized_api_base: attempt.normalized_api_base.clone(),
                subject: subject.clone(),
                cursor_key: namespace_key.clone(),
                epoch,
                nonce: session_nonce,
                expires_at,
                safe_user: safe_user.clone(),
            });
            state.tombstone = None;
            state.latest_attempt = None;
            Ok(())
        })?;
        // 普通原生入口的 commit 没有 Flutter ACK 阶段；Flutter helper 会在本函数返回后
        // 且仍持有同一认证锁时重新安装 pending 门禁。
        self.pending_ui_acceptance = None;
        self.trusted_address_book_reset = None;
        self.personal_hash_fence = next_personal_hash_fence;
        self.clear_active_personal_hash_material();
        self.commercial_personal_guid = None;
        self.personal_hash_mutations_in_flight = 0;
        Ok(snapshot_from_state(&state))
    }

    #[cfg(any(test, feature = "flutter"))]
    fn commit_auth_attempt_with_local_owner(
        &mut self,
        attempt: &AuthAttempt,
        access_token: String,
        safe_user: AuthSafeUser,
        expires_at: Option<i64>,
        publish_local_owner: impl FnOnce(&AuthSnapshot) -> bool,
    ) -> ResultType<AuthSnapshot> {
        let snapshot = self.commit_auth_attempt(attempt, access_token, safe_user, expires_at)?;
        let pending_handle = self
            .store
            .snapshot()
            .session
            .as_ref()
            .map(handle_from_session)
            .ok_or_else(|| anyhow!("Committed auth session is missing before UI acceptance"))?;
        self.pending_ui_acceptance = Some(pending_handle.clone());
        if publish_local_owner(&snapshot) {
            return Ok(snapshot);
        }

        if !self.clear_auth_session_if_current(&pending_handle)? {
            bail!("Committed auth session changed before local rollback");
        }
        bail!("Committed auth result lost its local owner");
    }

    pub fn is_auth_attempt_current(&self, attempt: &AuthAttempt) -> bool {
        state_attempt_is_current(&self.store.snapshot(), attempt)
    }

    /// 调用方已经用本地 task owner 精确匹配 attempt 后，再验证其提交结果仍是最新会话。
    /// attempt_counter 可让“新 attempt 已开始但尚未提交”的旧结果立即失效。
    #[cfg(any(test, feature = "flutter"))]
    pub(crate) fn committed_auth_attempt_result_is_current(
        &self,
        attempt: &AuthAttempt,
        handle: &CredentialedRequestHandle,
    ) -> bool {
        let state = self.store.snapshot();
        state.attempt_counter == attempt.attempt_id
            && state.logout_generation == attempt.logout_generation
            && state.latest_attempt.is_none()
            && state_handle_is_current(&state, handle)
    }

    #[cfg(any(test, feature = "flutter"))]
    fn acknowledge_committed_auth_attempt_result(
        &mut self,
        attempt: &AuthAttempt,
        handle: &CredentialedRequestHandle,
        acknowledge_local_owner: impl FnOnce() -> bool,
    ) -> bool {
        let state = self.store.snapshot();
        if !self.committed_auth_attempt_result_is_current(attempt, handle)
            || !self
                .pending_ui_acceptance
                .as_ref()
                .is_some_and(|pending| state_handle_is_current(&state, pending))
            || !acknowledge_local_owner()
        {
            return false;
        }
        self.pending_ui_acceptance = None;
        true
    }

    pub fn cancel_auth_attempt(&mut self, attempt: &AuthAttempt) -> ResultType<bool> {
        if !self.is_auth_attempt_current(attempt) {
            return Ok(false);
        }
        let mut cancelled = false;
        self.store.update(|state| {
            if state_attempt_is_current(state, attempt) {
                state.latest_attempt = None;
                cancelled = true;
            }
            Ok(())
        })?;
        Ok(cancelled)
    }

    pub fn begin_logout_current(
        &mut self,
        identity: DeviceIdentitySnapshot,
    ) -> ResultType<Option<PendingLogoutTicket>> {
        let mut result = None;
        self.store.update(|state| {
            if state.session.is_some() && state.pending_logouts.len() >= MAX_PENDING_LOGOUTS {
                bail!("Pending logout queue is full");
            }
            state.auth_epoch = checked_increment(state.auth_epoch, "epoch")?;
            state.logout_generation =
                checked_increment(state.logout_generation, "logout generation")?;
            let tombstone_nonce = random_nonce();
            state.latest_attempt = None;
            if let Some(session) = state.session.take() {
                let subject_hash = subject_sha256(&session.subject);
                let ticket = PendingLogoutTicket {
                    ticket_id: hbb_common::uuid::Uuid::new_v4().to_string(),
                    normalized_api_base: session.normalized_api_base.clone(),
                    logout_generation: state.logout_generation,
                };
                state.pending_logouts.push(PendingLogout {
                    ticket_id: ticket.ticket_id.clone(),
                    normalized_api_base: ticket.normalized_api_base.clone(),
                    subject_sha256: subject_hash.clone(),
                    logout_generation: ticket.logout_generation,
                    access_token: session.access_token,
                    token_expires_at: session.expires_at,
                    device_id: identity.id.clone(),
                    device_uuid: identity.uuid.clone(),
                    attempt_count: 0,
                    retry_after_unix_ms: 0,
                });
                if let Some(namespace) = state.namespaces.get_mut(&session.cursor_key) {
                    namespace.capability = AddressBookCapability::Unknown;
                    namespace.force_full_pending = true;
                    namespace.pro_epoch = None;
                }
                state.tombstone = Some(AuthTombstone {
                    epoch: state.auth_epoch,
                    nonce: tombstone_nonce,
                    logout_generation: state.logout_generation,
                    normalized_api_base: Some(session.normalized_api_base),
                    subject_sha256: Some(subject_hash),
                });
                result = Some(ticket);
            } else {
                state.tombstone = Some(AuthTombstone {
                    epoch: state.auth_epoch,
                    nonce: tombstone_nonce,
                    logout_generation: state.logout_generation,
                    normalized_api_base: None,
                    subject_sha256: None,
                });
            }
            Ok(())
        })?;
        self.pending_ui_acceptance = None;
        self.trusted_address_book_reset = None;
        self.clear_personal_hash_state()?;
        Ok(result)
    }

    pub fn reconcile_effective_api_base_before_publish(
        &mut self,
        old_effective_api_base: &str,
        new_effective_api_base: &str,
        identity: DeviceIdentitySnapshot,
    ) -> ResultType<EffectiveApiBaseTransition> {
        let old_normalized = normalize_optional_effective_api_base(old_effective_api_base);
        let new_normalized = normalize_optional_effective_api_base(new_effective_api_base)?;
        let state = self.store.snapshot();
        let snapshot = snapshot_from_state(&state);
        let base_changed = old_normalized
            .as_ref()
            .map_or(true, |old| old != &new_normalized);
        let session_mismatch = snapshot
            .session
            .as_ref()
            .is_some_and(|session| new_normalized.as_ref() != Some(&session.normalized_api_base));
        let attempt_mismatch = state
            .latest_attempt
            .as_ref()
            .is_some_and(|attempt| new_normalized.as_ref() != Some(&attempt.normalized_api_base));
        let session_invalidated = snapshot.session.is_some() && (base_changed || session_mismatch);

        // API 来源切换不仅要清理已登录 session，还必须持久化失效尚在网络中的登录
        // attempt；否则 A 的迟到登录响应可在 B 已发布后重新提交。
        if base_changed || session_mismatch || attempt_mismatch {
            self.begin_logout_current(identity)?;
        }

        Ok(EffectiveApiBaseTransition {
            base_changed,
            session_invalidated,
            snapshot: self.snapshot(),
        })
    }

    pub fn clear_auth_session_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
    ) -> ResultType<bool> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            return Ok(false);
        }
        let mut cleared = false;
        self.store.update(|state| {
            if !state_handle_is_current(state, handle) {
                return Ok(());
            }
            let Some(session) = state.session.take() else {
                return Ok(());
            };
            state.auth_epoch = checked_increment(state.auth_epoch, "epoch")?;
            if let Some(namespace) = state.namespaces.get_mut(&session.cursor_key) {
                namespace.capability = AddressBookCapability::Unknown;
                namespace.force_full_pending = true;
                namespace.pro_epoch = None;
            }
            state.tombstone = Some(AuthTombstone {
                epoch: state.auth_epoch,
                nonce: random_nonce(),
                logout_generation: state.logout_generation,
                normalized_api_base: Some(session.normalized_api_base),
                subject_sha256: Some(subject_sha256(&session.subject)),
            });
            cleared = true;
            Ok(())
        })?;
        if cleared {
            self.pending_ui_acceptance = None;
            self.trusted_address_book_reset = None;
            self.clear_personal_hash_state()?;
        }
        Ok(cleared)
    }

    pub fn credentialed_request_handle(
        &self,
        target_url: &str,
    ) -> ResultType<CredentialedRequestHandle> {
        let state = self.store.snapshot();
        let session = state
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("No active native authentication session"))?;
        if self
            .pending_ui_acceptance
            .as_ref()
            .is_some_and(|pending| state_handle_is_current(&state, pending))
        {
            bail!("Native authentication session is waiting for UI acceptance");
        }
        validate_target_against_base(&session.normalized_api_base, target_url)?;
        Ok(handle_from_session(session))
    }

    pub fn is_request_current(&self, handle: &CredentialedRequestHandle) -> bool {
        let state = self.store.snapshot();
        !self
            .pending_ui_acceptance
            .as_ref()
            .is_some_and(|pending| state_handle_is_current(&state, pending))
            && state_handle_is_current(&state, handle)
    }

    /// 记录服务端明确返回的 reset 授权。
    ///
    /// 该授权必须由持有当前代 credentialed handle 的原生 worker 登记；Dart 侧传入的
    /// `allow_reset` 只表达“本次 ACK 期望使用 reset”，不能自行授予 cursor 降版权限。
    pub fn authorize_address_book_reset(
        &mut self,
        handle: &CredentialedRequestHandle,
        expected_cursor: u64,
        target_cursor: u64,
    ) -> ResultType<bool> {
        if expected_cursor > MAX_SAFE_INTEGER || target_cursor > MAX_SAFE_INTEGER {
            bail!("Address book reset cursor exceeds the safe integer range");
        }
        let current = self.store.snapshot();
        if !state_handle_is_current(&current, handle)
            || current
                .namespaces
                .get(&handle.cursor_key)
                .map_or(true, |namespace| namespace.cursor != expected_cursor)
        {
            return Ok(false);
        }
        self.trusted_address_book_reset = Some(TrustedAddressBookReset::new(
            handle,
            expected_cursor,
            target_cursor,
        ));
        Ok(true)
    }

    pub fn clear_address_book_reset_authorization_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
    ) {
        if self
            .trusted_address_book_reset
            .as_ref()
            .is_some_and(|authorization| {
                authorization.normalized_api_base == handle.normalized_api_base
                    && authorization.namespace == handle.namespace
                    && authorization.session_epoch == handle.session_epoch
                    && authorization.session_nonce == handle.session_nonce
                    && authorization.cursor_key == handle.cursor_key
            })
        {
            self.trusted_address_book_reset = None;
        }
    }

    pub(crate) fn credentialed_context(
        &self,
        handle: &CredentialedRequestHandle,
        target_url: &str,
    ) -> ResultType<CredentialedRequestContext> {
        let state = self.store.snapshot();
        let session = state
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("No active native authentication session"))?;
        if self
            .pending_ui_acceptance
            .as_ref()
            .is_some_and(|pending| state_handle_is_current(&state, pending))
        {
            bail!("Native authentication session is waiting for UI acceptance");
        }
        if !state_handle_is_current(&state, handle) {
            bail!("Credentialed request context is stale");
        }
        validate_target_against_base(&session.normalized_api_base, target_url)?;
        Ok(CredentialedRequestContext {
            handle: handle.clone(),
            access_token: session.access_token.clone(),
        })
    }

    pub fn compare_and_set_cursor(
        &mut self,
        handle: &CredentialedRequestHandle,
        expected_cursor: u64,
        target_cursor: u64,
        allow_reset: bool,
    ) -> ResultType<bool> {
        if expected_cursor > MAX_SAFE_INTEGER || target_cursor > MAX_SAFE_INTEGER {
            bail!("Address book cursor exceeds the safe integer range");
        }
        if !allow_reset && target_cursor < expected_cursor {
            bail!("Address book cursor cannot move backwards without a trusted reset");
        }
        if target_cursor < expected_cursor
            && self
                .trusted_address_book_reset
                .as_ref()
                .map_or(true, |authorization| {
                    !authorization.matches(handle, expected_cursor, target_cursor)
                })
        {
            bail!("Address book cursor reset was not authorized by the current worker response");
        }
        if !self.is_request_current(handle) {
            return Ok(false);
        }
        let mut changed = false;
        self.store.update(|state| {
            if !state_handle_is_current(state, handle) {
                return Ok(());
            }
            let namespace = state
                .namespaces
                .get_mut(&handle.cursor_key)
                .ok_or_else(|| anyhow!("Address book namespace is missing"))?;
            if namespace.cursor != expected_cursor {
                return Ok(());
            }
            namespace.cursor = target_cursor;
            changed = true;
            Ok(())
        })?;
        if changed {
            self.trusted_address_book_reset = None;
        }
        Ok(changed)
    }

    pub fn complete_address_book_pull(
        &mut self,
        handle: &CredentialedRequestHandle,
        expected_cursor: u64,
        target_cursor: u64,
        allow_reset: bool,
    ) -> ResultType<bool> {
        if expected_cursor > MAX_SAFE_INTEGER || target_cursor > MAX_SAFE_INTEGER {
            bail!("Address book cursor exceeds the safe integer range");
        }
        if !allow_reset && target_cursor < expected_cursor {
            bail!("Address book cursor cannot move backwards without a trusted reset");
        }
        if target_cursor < expected_cursor
            && self
                .trusted_address_book_reset
                .as_ref()
                .map_or(true, |authorization| {
                    !authorization.matches(handle, expected_cursor, target_cursor)
                })
        {
            bail!("Address book cursor reset was not authorized by the current worker response");
        }
        let current = self.store.snapshot();
        let cursor_matches = match current.namespaces.get(&handle.cursor_key) {
            Some(namespace) => namespace.cursor == expected_cursor,
            None => false,
        };
        if !state_handle_is_current(&current, handle) || !cursor_matches {
            return Ok(false);
        }

        let mut completed = false;
        self.store.update(|state| {
            if !state_handle_is_current(state, handle) {
                return Ok(());
            }
            let namespace = state
                .namespaces
                .get_mut(&handle.cursor_key)
                .ok_or_else(|| anyhow!("Address book namespace is missing"))?;
            if namespace.cursor != expected_cursor {
                return Ok(());
            }
            namespace.cursor = target_cursor;
            namespace.capability = AddressBookCapability::Issue9V2;
            namespace.force_full_pending = false;
            namespace.pro_epoch = Some(handle.session_epoch);
            completed = true;
            Ok(())
        })?;
        if completed {
            self.trusted_address_book_reset = None;
            self.invalidate_personal_hash_state_in_current_session()?;
        }
        Ok(completed)
    }

    pub fn set_address_book_capability(
        &mut self,
        handle: &CredentialedRequestHandle,
        capability: AddressBookCapability,
        force_full_pending: bool,
    ) -> ResultType<bool> {
        if matches!(capability, AddressBookCapability::Unknown) && !force_full_pending {
            bail!("Unknown address book capability must retain a force-full probe");
        }
        if matches!(capability, AddressBookCapability::Issue9V2) && !force_full_pending {
            bail!("Issue 9 completion must atomically commit its cursor");
        }
        if matches!(
            capability,
            AddressBookCapability::Legacy | AddressBookCapability::CommercialMulti
        ) && force_full_pending
        {
            bail!("Completed legacy address book capability cannot retain force-full pending");
        }
        if !self.is_request_current(handle) {
            return Ok(false);
        }
        let mut changed = false;
        self.store.update(|state| {
            if !state_handle_is_current(state, handle) {
                return Ok(());
            }
            let namespace = state
                .namespaces
                .get_mut(&handle.cursor_key)
                .ok_or_else(|| anyhow!("Address book namespace is missing"))?;
            namespace.capability = capability;
            namespace.force_full_pending = force_full_pending;
            namespace.pro_epoch = match capability {
                AddressBookCapability::Legacy | AddressBookCapability::CommercialMulti => {
                    Some(handle.session_epoch)
                }
                AddressBookCapability::Unknown | AddressBookCapability::Issue9V2 => None,
            };
            changed = true;
            Ok(())
        })?;
        if changed && !matches!(capability, AddressBookCapability::Issue9V2) {
            self.trusted_address_book_reset = None;
        }
        if changed
            && matches!(
                capability,
                AddressBookCapability::Unknown | AddressBookCapability::Issue9V2
            )
        {
            self.invalidate_personal_hash_state_in_current_session()?;
        }
        Ok(changed)
    }

    fn replace_personal_hash_allowlist(
        &mut self,
        handle: &CredentialedRequestHandle,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> ResultType<bool> {
        let state = self.store.snapshot();
        if !state_handle_is_current(&state, handle) {
            return Ok(false);
        }
        let session = state
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("No active native authentication session"))?;
        self.personal_hash_allowlist = Some(PersonalHashAllowlist {
            normalized_api_base: session.normalized_api_base.clone(),
            namespace: session.subject.namespace_component(),
            session_epoch: session.epoch,
            session_nonce: session.nonce.clone(),
            generation_nonce: random_nonce(),
            source,
            hashes,
        });
        Ok(true)
    }

    pub fn issue_personal_hash_receipt(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> ResultType<Option<String>> {
        if !self.personal_hash_response_is_current(handle, request_fence) {
            return Ok(None);
        }
        // 一旦收到新的 personal 完整响应，旧表立即失效；只有模型提交后消费 receipt 才重新激活。
        let receipt_fence = self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        let receipt_id = hbb_common::uuid::Uuid::new_v4().to_string();
        self.personal_hash_receipt = Some(PersonalHashReceipt {
            receipt_id: receipt_id.clone(),
            handle: handle.clone(),
            fence: receipt_fence,
            source,
            hashes,
        });
        Ok(Some(receipt_id))
    }

    pub fn register_commercial_personal_guid(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: String,
    ) -> ResultType<bool> {
        if guid.is_empty() || guid.len() > 512 || guid.chars().any(char::is_control) {
            bail!("商业个人地址簿 guid 无效");
        }
        if !self.personal_hash_response_is_current(handle, request_fence) {
            return Ok(false);
        }
        // GUID 本身也是 personal 来源证明。推进栅栏，拒绝任何在该发现响应前启动的分页。
        self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        self.commercial_personal_guid = Some((handle.clone(), guid));
        Ok(true)
    }

    pub fn is_current_commercial_personal_guid(
        &self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
    ) -> bool {
        self.personal_hash_response_is_current(handle, request_fence)
            && self.commercial_personal_guid.as_ref().is_some_and(
                |(expected_handle, expected_guid)| {
                    same_session_handle(expected_handle, handle) && expected_guid == guid
                },
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_commercial_personal_hash_page(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
        guid: &str,
        page: usize,
        page_size: usize,
        total: usize,
        items: Vec<(String, Option<Vec<u8>>)>,
    ) -> ResultType<Option<String>> {
        if !self.personal_hash_response_is_current(handle, request_fence) {
            return Ok(None);
        }
        if !self.is_current_commercial_personal_guid(handle, request_fence, guid) {
            return Ok(None);
        }
        if page == 0 || page_size == 0 || total > 100_000 {
            bail!("商业个人地址簿分页参数无效");
        }
        if page == 1 {
            self.personal_hash_allowlist = None;
            self.personal_hash_receipt = None;
            self.commercial_personal_hash_accumulator = Some(CommercialPersonalHashAccumulator {
                handle: handle.clone(),
                fence: request_fence,
                guid: guid.to_owned(),
                total,
                page_size,
                next_page: 1,
                received: 0,
                seen_ids: BTreeSet::new(),
                hashes: BTreeMap::new(),
            });
        }
        let accumulator = self
            .commercial_personal_hash_accumulator
            .as_mut()
            .ok_or_else(|| anyhow!("商业个人地址簿缺少第一页"))?;
        if accumulator.handle != *handle
            || accumulator.fence != request_fence
            || accumulator.guid != guid
            || accumulator.total != total
            || accumulator.page_size != page_size
            || accumulator.next_page != page
            || accumulator.received > total
        {
            bail!("商业个人地址簿分页状态漂移");
        }
        let remaining = total - accumulator.received;
        let expected_count = remaining.min(page_size);
        if items.len() != expected_count {
            bail!("商业个人地址簿分页数量不完整");
        }
        for (device_id, hash) in items {
            if !accumulator.seen_ids.insert(device_id.clone()) {
                bail!("商业个人地址簿包含重复设备");
            }
            if let Some(hash) = hash {
                accumulator.hashes.insert(device_id, hash);
            }
        }
        accumulator.received = accumulator
            .received
            .checked_add(expected_count)
            .ok_or_else(|| anyhow!("商业个人地址簿分页计数溢出"))?;
        accumulator.next_page = accumulator
            .next_page
            .checked_add(1)
            .ok_or_else(|| anyhow!("商业个人地址簿页码溢出"))?;
        if accumulator.received != total {
            return Ok(None);
        }
        let completed = self
            .commercial_personal_hash_accumulator
            .take()
            .ok_or_else(|| anyhow!("商业个人地址簿分页状态缺失"))?;
        self.issue_personal_hash_receipt(
            handle,
            request_fence,
            PersonalHashSource::CommercialPersonal,
            completed.hashes,
        )
    }

    pub fn commit_personal_hash_receipt(
        &mut self,
        handle: &CredentialedRequestHandle,
        receipt_id: &str,
    ) -> ResultType<bool> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            return Ok(false);
        }
        let receipt = self
            .personal_hash_receipt
            .take()
            .ok_or_else(|| anyhow!("个人地址簿 hash receipt 不存在或已消费"))?;
        if receipt.receipt_id != receipt_id
            || receipt.handle != *handle
            || receipt.fence != self.personal_hash_fence
            || self.personal_hash_mutations_in_flight != 0
        {
            self.personal_hash_allowlist = None;
            bail!("个人地址簿 hash receipt 与当前请求不匹配");
        }
        self.replace_personal_hash_allowlist(handle, receipt.source, receipt.hashes)
    }

    pub fn clear_personal_hash_allowlist_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
    ) -> ResultType<bool> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            return Ok(false);
        }
        self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        Ok(true)
    }

    pub fn invalidate_personal_hash_provenance_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> ResultType<bool> {
        if !self.personal_hash_response_is_current(handle, request_fence) {
            return Ok(false);
        }
        self.advance_personal_hash_fence()?;
        self.clear_active_personal_hash_material();
        self.commercial_personal_guid = None;
        // 若失效发生在并发 mutation 期间，pending 必须由对应 finish 配对递减。
        Ok(true)
    }

    pub fn personal_hash_request_fence(
        &self,
        handle: &CredentialedRequestHandle,
    ) -> ResultType<u64> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            bail!("个人地址簿请求句柄已失效");
        }
        Ok(self.personal_hash_fence)
    }

    pub fn personal_hash_response_is_current(
        &self,
        handle: &CredentialedRequestHandle,
        request_fence: u64,
    ) -> bool {
        state_handle_is_current(&self.store.snapshot(), handle)
            && self.personal_hash_fence == request_fence
            && self.personal_hash_mutations_in_flight == 0
    }

    /// 在 personal 写请求发出前原子确认其来源并建立失效栅栏。
    ///
    /// legacy 写入传 `None`；商业写入传 URL 中的地址簿 GUID，只有当前已由
    /// `/api/ab/personal` 原生响应登记的 GUID 才会被视为 personal mutation。
    pub fn begin_personal_hash_mutation_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
        commercial_guid: Option<&str>,
    ) -> ResultType<bool> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            return Ok(false);
        }
        if commercial_guid.is_some_and(|guid| {
            !self.commercial_personal_guid.as_ref().is_some_and(
                |(expected_handle, expected_guid)| {
                    same_session_handle(expected_handle, handle) && expected_guid == guid
                },
            )
        }) {
            return Ok(false);
        }
        let next_fence = checked_increment(self.personal_hash_fence, "personal hash fence")?;
        let next_pending = checked_increment(
            self.personal_hash_mutations_in_flight,
            "personal hash mutations in flight",
        )?;
        self.personal_hash_fence = next_fence;
        self.personal_hash_mutations_in_flight = next_pending;
        self.clear_active_personal_hash_material();
        Ok(true)
    }

    /// 无论 HTTP 成功或失败都必须结束 mutation；服务端可能已在传输错误前提交。
    pub fn finish_personal_hash_mutation_if_current(
        &mut self,
        handle: &CredentialedRequestHandle,
    ) -> ResultType<bool> {
        if !state_handle_is_current(&self.store.snapshot(), handle) {
            return Ok(false);
        }
        if self.personal_hash_mutations_in_flight == 0 {
            bail!("个人地址簿 mutation 栅栏缺少匹配的开始");
        }
        let next_fence = checked_increment(self.personal_hash_fence, "personal hash fence")?;
        self.personal_hash_fence = next_fence;
        self.personal_hash_mutations_in_flight -= 1;
        self.clear_active_personal_hash_material();
        Ok(true)
    }

    pub fn personal_hash_for_peer(&self, peer_id: &str) -> Option<Vec<u8>> {
        if self.personal_hash_mutations_in_flight != 0 {
            return None;
        }
        let state = self.store.snapshot();
        let session = state.session.as_ref()?;
        let capability = state.namespaces.get(&session.cursor_key)?.capability;
        let allowlist = self.personal_hash_allowlist.as_ref()?;
        if !allowlist.matches_session(session) {
            return None;
        }
        if !matches!(
            (capability, allowlist.source),
            (
                AddressBookCapability::Legacy,
                PersonalHashSource::LegacyPersonal
            ) | (
                AddressBookCapability::CommercialMulti,
                PersonalHashSource::CommercialPersonal
            )
        ) {
            return None;
        }
        allowlist.hashes.get(peer_id).cloned()
    }

    pub(crate) fn personal_hash_connection_capability(
        &self,
        peer_id: &str,
        expected_hash: &[u8],
    ) -> Option<PersonalHashConnectionCapability> {
        let hash = self.personal_hash_for_peer(peer_id)?;
        if hash != expected_hash {
            return None;
        }
        let state = self.store.snapshot();
        let session = state.session.as_ref()?;
        let allowlist = self.personal_hash_allowlist.as_ref()?;
        Some(PersonalHashConnectionCapability {
            normalized_api_base: session.normalized_api_base.clone(),
            namespace: session.subject.namespace_component(),
            cursor_key: session.cursor_key.clone(),
            auth_epoch: state.auth_epoch,
            logout_generation: state.logout_generation,
            session_epoch: session.epoch,
            session_nonce: session.nonce.clone(),
            fence: self.personal_hash_fence,
            generation_nonce: allowlist.generation_nonce.clone(),
            source: allowlist.source,
            peer_id: peer_id.to_owned(),
            hash,
        })
    }

    pub(crate) fn personal_hash_connection_capability_is_current(
        &self,
        capability: &PersonalHashConnectionCapability,
    ) -> bool {
        self.personal_hash_connection_capability(&capability.peer_id, &capability.hash)
            .is_some_and(|current| current == *capability)
    }

    pub fn mark_pro_if_current(&mut self, handle: &CredentialedRequestHandle) -> ResultType<bool> {
        let current = self.store.snapshot();
        if !state_handle_is_current(&current, handle) {
            return Ok(false);
        }
        if current
            .namespaces
            .get(&handle.cursor_key)
            .is_some_and(|namespace| namespace.pro_epoch == Some(handle.session_epoch))
        {
            return Ok(false);
        }
        let mut changed = false;
        self.store.update(|state| {
            if !state_handle_is_current(state, handle) {
                return Ok(());
            }
            let namespace = state
                .namespaces
                .get_mut(&handle.cursor_key)
                .ok_or_else(|| anyhow!("Address book namespace is missing"))?;
            if namespace.pro_epoch == Some(handle.session_epoch) {
                return Ok(());
            }
            namespace.pro_epoch = Some(handle.session_epoch);
            changed = true;
            Ok(())
        })?;
        Ok(changed)
    }

    pub fn pending_logout_tickets(&self) -> Vec<PendingLogoutTicket> {
        self.store
            .snapshot()
            .pending_logouts
            .into_iter()
            .map(|pending| PendingLogoutTicket {
                ticket_id: pending.ticket_id,
                normalized_api_base: pending.normalized_api_base,
                logout_generation: pending.logout_generation,
            })
            .collect()
    }

    pub(crate) fn pending_logout_request(
        &self,
        ticket: &PendingLogoutTicket,
    ) -> Option<PendingLogoutRequest> {
        self.store
            .snapshot()
            .pending_logouts
            .into_iter()
            .find(|pending| {
                pending.ticket_id == ticket.ticket_id
                    && pending.normalized_api_base == ticket.normalized_api_base
                    && pending.logout_generation == ticket.logout_generation
            })
            .map(|pending| PendingLogoutRequest {
                ticket: PendingLogoutTicket {
                    ticket_id: pending.ticket_id,
                    normalized_api_base: pending.normalized_api_base,
                    logout_generation: pending.logout_generation,
                },
                access_token: pending.access_token,
                device_identity: DeviceIdentitySnapshot {
                    id: pending.device_id,
                    uuid: pending.device_uuid,
                },
                attempt_count: pending.attempt_count,
                retry_after_unix_ms: pending.retry_after_unix_ms,
            })
    }

    pub fn complete_pending_logout(&mut self, ticket: &PendingLogoutTicket) -> ResultType<bool> {
        if !self.store.snapshot().pending_logouts.iter().any(|pending| {
            pending.ticket_id == ticket.ticket_id
                && pending.normalized_api_base == ticket.normalized_api_base
                && pending.logout_generation == ticket.logout_generation
        }) {
            return Ok(false);
        }
        let mut removed = false;
        self.store.update(|state| {
            let previous_len = state.pending_logouts.len();
            state.pending_logouts.retain(|pending| {
                !(pending.ticket_id == ticket.ticket_id
                    && pending.normalized_api_base == ticket.normalized_api_base
                    && pending.logout_generation == ticket.logout_generation)
            });
            removed = previous_len != state.pending_logouts.len();
            Ok(())
        })?;
        Ok(removed)
    }

    pub fn record_pending_logout_failure(
        &mut self,
        ticket: &PendingLogoutTicket,
        retry_after_unix_ms: u64,
    ) -> ResultType<bool> {
        let Some(current) = self
            .store
            .snapshot()
            .pending_logouts
            .into_iter()
            .find(|pending| {
                pending.ticket_id == ticket.ticket_id
                    && pending.normalized_api_base == ticket.normalized_api_base
                    && pending.logout_generation == ticket.logout_generation
            })
        else {
            return Ok(false);
        };
        if current.attempt_count == u32::MAX {
            bail!("Pending logout retry counter is exhausted");
        }
        let mut changed = false;
        self.store.update(|state| {
            let Some(pending) = state.pending_logouts.iter_mut().find(|pending| {
                pending.ticket_id == ticket.ticket_id
                    && pending.normalized_api_base == ticket.normalized_api_base
                    && pending.logout_generation == ticket.logout_generation
            }) else {
                return Ok(());
            };
            pending.attempt_count = pending
                .attempt_count
                .checked_add(1)
                .ok_or_else(|| anyhow!("Pending logout retry counter is exhausted"))?;
            pending.retry_after_unix_ms = retry_after_unix_ms;
            changed = true;
            Ok(())
        })?;
        Ok(changed)
    }
}

pub fn initialize_main_ui_auth(anchor: AuthAuthorityAnchor) -> ResultType<()> {
    require_trusted_main_ui_process()?;
    let directory = anchor.directory();
    if let Some(binding) = MAIN_UI_AUTH.get() {
        let same_authority = {
            let binding = binding
                .lock()
                .map_err(|_| anyhow!("Native auth binding lock is poisoned"))?;
            binding.authority_directory() == directory
        };
        if same_authority {
            // UI 重新初始化也视为新的桥接生命周期，旧 opaque 连接能力不得跨实例存活。
            crate::client::clear_native_conn_token_registry();
            return Ok(());
        }
        bail!("Native auth binding is already initialized for another authority");
    }
    let binding = AuthBinding::open(anchor)?;
    MAIN_UI_AUTH
        .set(Mutex::new(binding))
        .map_err(|_| anyhow!("Native auth binding initialization raced with another writer"))?;
    crate::client::clear_native_conn_token_registry();
    Ok(())
}

pub fn reset_local_auth_state(anchor: AuthAuthorityAnchor) -> ResultType<()> {
    require_trusted_main_ui_process()?;
    if MAIN_UI_AUTH.get().is_some() {
        bail!("Native auth state cannot be reset while the main UI binding is active");
    }
    let binding = AuthBinding::reset_corrupt(anchor)?;
    MAIN_UI_AUTH
        .set(Mutex::new(binding))
        .map_err(|_| anyhow!("Native auth binding initialization raced with another writer"))?;
    crate::client::clear_native_conn_token_registry();
    Ok(())
}

pub fn is_main_ui_auth_initialized() -> bool {
    MAIN_UI_AUTH.get().is_some()
}

pub fn auth_snapshot() -> ResultType<AuthSnapshot> {
    with_main_ui_auth(|binding| Ok(binding.snapshot()))
}

pub fn begin_auth_attempt(api_base: &str) -> ResultType<AuthAttempt> {
    with_main_ui_auth(|binding| binding.begin_auth_attempt(api_base))
}

pub fn commit_auth_attempt(
    attempt: &AuthAttempt,
    access_token: String,
    safe_user: AuthSafeUser,
    expires_at: Option<i64>,
) -> ResultType<AuthSnapshot> {
    let snapshot = with_main_ui_auth(|binding| {
        binding.commit_auth_attempt(attempt, access_token, safe_user, expires_at)
    })?;
    crate::client::clear_native_conn_token_registry();
    Ok(snapshot)
}

/// Flutter 登录把 durable commit 与本地 owner 标记放在同一认证锁内，避免其他入口插队。
/// 若本地 owner 已丢失，则在释放认证锁前按刚提交的 session 代次回滚，禁止留下不可见会话。
#[cfg(feature = "flutter")]
pub(crate) fn commit_auth_attempt_with_local_owner(
    attempt: &AuthAttempt,
    access_token: String,
    safe_user: AuthSafeUser,
    expires_at: Option<i64>,
    publish_local_owner: impl FnOnce(&AuthSnapshot) -> bool,
) -> ResultType<AuthSnapshot> {
    let result = with_main_ui_auth(|binding| {
        binding.commit_auth_attempt_with_local_owner(
            attempt,
            access_token,
            safe_user,
            expires_at,
            publish_local_owner,
        )
    });
    // commit 或条件回滚都可能改变当前会话代次；错误路径也必须清掉旧连接 token。
    crate::client::clear_native_conn_token_registry();
    result
}

pub fn is_auth_attempt_current(attempt: &AuthAttempt) -> bool {
    with_main_ui_auth(|binding| Ok(binding.is_auth_attempt_current(attempt))).unwrap_or(false)
}

/// 在认证权威锁内复验 attempt，再执行不回调 auth_binding 的本地状态提交。
#[cfg(feature = "flutter")]
pub(crate) fn with_current_auth_attempt<T>(
    attempt: &AuthAttempt,
    operation: impl FnOnce() -> T,
) -> Option<T> {
    with_main_ui_auth(|binding| {
        if !binding.is_auth_attempt_current(attempt) {
            return Ok(None);
        }
        Ok(Some(operation()))
    })
    .ok()
    .flatten()
}

/// 与上式相同，但用于 attempt 已被成功 commit 后的本地结果发布。
#[cfg(feature = "flutter")]
pub(crate) fn with_current_committed_auth_attempt_result<T>(
    attempt: &AuthAttempt,
    handle: &CredentialedRequestHandle,
    operation: impl FnOnce() -> T,
) -> Option<T> {
    with_main_ui_auth(|binding| {
        if !binding.committed_auth_attempt_result_is_current(attempt, handle) {
            return Ok(None);
        }
        Ok(Some(operation()))
    })
    .ok()
    .flatten()
}

/// 在同一认证锁内完成 exact committed 复验、本地 DTO 消费与 credentialed 门禁放行。
#[cfg(feature = "flutter")]
pub(crate) fn acknowledge_current_committed_auth_attempt_result(
    attempt: &AuthAttempt,
    handle: &CredentialedRequestHandle,
    acknowledge_local_owner: impl FnOnce() -> bool,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        Ok(binding.acknowledge_committed_auth_attempt_result(
            attempt,
            handle,
            acknowledge_local_owner,
        ))
    })
}

pub fn cancel_auth_attempt(attempt: &AuthAttempt) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.cancel_auth_attempt(attempt))
}

pub fn begin_logout_current(
    identity: DeviceIdentitySnapshot,
) -> ResultType<Option<PendingLogoutTicket>> {
    let result = with_main_ui_auth(|binding| binding.begin_logout_current(identity))?;
    crate::client::clear_native_conn_token_registry();
    Ok(result)
}

pub fn reconcile_effective_api_base_before_publish(
    old_effective_api_base: &str,
    new_effective_api_base: &str,
    identity: DeviceIdentitySnapshot,
) -> ResultType<EffectiveApiBaseTransition> {
    let before = auth_snapshot()?;
    let before_generation = (before.auth_epoch, before.logout_generation);
    let transition = with_main_ui_auth(|binding| {
        binding.reconcile_effective_api_base_before_publish(
            old_effective_api_base,
            new_effective_api_base,
            identity,
        )
    })?;
    if before_generation
        != (
            transition.snapshot.auth_epoch,
            transition.snapshot.logout_generation,
        )
    {
        crate::client::clear_native_conn_token_registry();
    }
    Ok(transition)
}

pub fn credentialed_request_handle(target_url: &str) -> ResultType<CredentialedRequestHandle> {
    with_main_ui_auth(|binding| binding.credentialed_request_handle(target_url))
}

pub fn is_request_current(handle: &CredentialedRequestHandle) -> bool {
    with_main_ui_auth(|binding| Ok(binding.is_request_current(handle))).unwrap_or(false)
}

/// 在同一认证互斥锁内重验 generation 并执行同步提交，避免 logout 与本地副作用交错。
pub fn with_current_credentialed_request<T>(
    handle: &CredentialedRequestHandle,
    operation: impl FnOnce() -> ResultType<T>,
) -> ResultType<Option<T>> {
    with_main_ui_auth(|binding| {
        if !binding.is_request_current(handle) {
            return Ok(None);
        }
        operation().map(Some)
    })
}

pub fn authorize_address_book_reset(
    handle: &CredentialedRequestHandle,
    expected_cursor: u64,
    target_cursor: u64,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.authorize_address_book_reset(handle, expected_cursor, target_cursor)
    })
}

pub fn clear_address_book_reset_authorization_if_current(
    handle: &CredentialedRequestHandle,
) -> ResultType<()> {
    with_main_ui_auth(|binding| {
        binding.clear_address_book_reset_authorization_if_current(handle);
        Ok(())
    })
}

pub fn clear_auth_session_if_current(handle: &CredentialedRequestHandle) -> ResultType<bool> {
    let cleared = with_main_ui_auth(|binding| binding.clear_auth_session_if_current(handle))?;
    if cleared {
        crate::client::clear_native_conn_token_registry();
    }
    Ok(cleared)
}

pub fn compare_and_set_cursor(
    handle: &CredentialedRequestHandle,
    expected_cursor: u64,
    target_cursor: u64,
    allow_reset: bool,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.compare_and_set_cursor(handle, expected_cursor, target_cursor, allow_reset)
    })
}

pub fn complete_address_book_pull(
    handle: &CredentialedRequestHandle,
    expected_cursor: u64,
    target_cursor: u64,
    allow_reset: bool,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.complete_address_book_pull(handle, expected_cursor, target_cursor, allow_reset)
    })
}

pub fn set_address_book_capability(
    handle: &CredentialedRequestHandle,
    capability: AddressBookCapability,
    force_full_pending: bool,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.set_address_book_capability(handle, capability, force_full_pending)
    })
}

pub fn issue_personal_hash_receipt(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    source: PersonalHashSource,
    hashes: BTreeMap<String, Vec<u8>>,
) -> ResultType<Option<String>> {
    with_main_ui_auth(|binding| {
        binding.issue_personal_hash_receipt(handle, request_fence, source, hashes)
    })
}

pub fn register_commercial_personal_guid(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    guid: String,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.register_commercial_personal_guid(handle, request_fence, guid)
    })
}

pub fn is_current_commercial_personal_guid(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    guid: &str,
) -> bool {
    with_main_ui_auth(|binding| {
        Ok(binding.is_current_commercial_personal_guid(handle, request_fence, guid))
    })
    .unwrap_or(false)
}

pub fn observe_commercial_personal_hash_page(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
    guid: &str,
    page: usize,
    page_size: usize,
    total: usize,
    items: Vec<(String, Option<Vec<u8>>)>,
) -> ResultType<Option<String>> {
    with_main_ui_auth(|binding| {
        binding.observe_commercial_personal_hash_page(
            handle,
            request_fence,
            guid,
            page,
            page_size,
            total,
            items,
        )
    })
}

pub fn commit_personal_hash_receipt(
    handle: &CredentialedRequestHandle,
    receipt_id: &str,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.commit_personal_hash_receipt(handle, receipt_id))
}

pub fn clear_personal_hash_allowlist_if_current(
    handle: &CredentialedRequestHandle,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.clear_personal_hash_allowlist_if_current(handle))
}

pub fn invalidate_personal_hash_provenance_if_current(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.invalidate_personal_hash_provenance_if_current(handle, request_fence)
    })
}

pub fn personal_hash_request_fence(handle: &CredentialedRequestHandle) -> ResultType<u64> {
    with_main_ui_auth(|binding| binding.personal_hash_request_fence(handle))
}

pub fn personal_hash_response_is_current(
    handle: &CredentialedRequestHandle,
    request_fence: u64,
) -> bool {
    with_main_ui_auth(
        |binding| Ok(binding.personal_hash_response_is_current(handle, request_fence)),
    )
    .unwrap_or(false)
}

pub fn begin_personal_hash_mutation_if_current(
    handle: &CredentialedRequestHandle,
    commercial_guid: Option<&str>,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| {
        binding.begin_personal_hash_mutation_if_current(handle, commercial_guid)
    })
}

pub fn finish_personal_hash_mutation_if_current(
    handle: &CredentialedRequestHandle,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.finish_personal_hash_mutation_if_current(handle))
}

pub fn personal_hash_for_peer(peer_id: &str) -> Option<Vec<u8>> {
    match with_main_ui_auth(|binding| Ok(binding.personal_hash_for_peer(peer_id))) {
        Ok(hash) => hash,
        Err(_) => None,
    }
}

pub(crate) fn personal_hash_connection_capability(
    peer_id: &str,
    expected_hash: &[u8],
) -> Option<PersonalHashConnectionCapability> {
    with_main_ui_auth(|binding| {
        Ok(binding.personal_hash_connection_capability(peer_id, expected_hash))
    })
    .ok()
    .flatten()
}

pub(crate) fn personal_hash_connection_capability_is_current(
    capability: &PersonalHashConnectionCapability,
) -> bool {
    with_main_ui_auth(|binding| {
        Ok(binding.personal_hash_connection_capability_is_current(capability))
    })
    .unwrap_or(false)
}

pub fn mark_pro_if_current(handle: &CredentialedRequestHandle) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.mark_pro_if_current(handle))
}

pub fn complete_pending_logout(ticket: &PendingLogoutTicket) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.complete_pending_logout(ticket))
}

pub fn record_pending_logout_failure(
    ticket: &PendingLogoutTicket,
    retry_after_unix_ms: u64,
) -> ResultType<bool> {
    with_main_ui_auth(|binding| binding.record_pending_logout_failure(ticket, retry_after_unix_ms))
}

pub(crate) fn credentialed_context(
    handle: &CredentialedRequestHandle,
    target_url: &str,
) -> ResultType<CredentialedRequestContext> {
    with_main_ui_auth(|binding| binding.credentialed_context(handle, target_url))
}

pub fn pending_logout_tickets() -> ResultType<Vec<PendingLogoutTicket>> {
    with_main_ui_auth(|binding| Ok(binding.pending_logout_tickets()))
}

pub async fn retry_pending_logout(
    ticket: &PendingLogoutTicket,
) -> ResultType<PendingLogoutOutcome> {
    let request = with_main_ui_auth(|binding| Ok(binding.pending_logout_request(ticket)))?;
    let Some(request) = request else {
        return Ok(PendingLogoutOutcome::Missing);
    };
    if request.retry_after_unix_ms > unix_time_ms() {
        return Ok(PendingLogoutOutcome::Retained {
            status: None,
            retry_after_unix_ms: request.retry_after_unix_ms,
        });
    }
    let target = endpoint_under_base(&request.ticket.normalized_api_base, "api/logout")?;
    let body = logout_identity_body(&request.device_identity)?;
    let http_request =
        crate::common::StrictHttpRequest::new(crate::common::StrictHttpMethod::Post, target)
            .json_body(body)
            .timeout(std::time::Duration::from_secs(10));
    let response =
        crate::common::strict_http_request_one_shot_bearer(http_request, request.access_token)
            .await;
    match response {
        Ok(response) if (200..300).contains(&response.status) || response.status == 401 => {
            let _ = complete_pending_logout(ticket)?;
            Ok(PendingLogoutOutcome::Revoked)
        }
        Ok(response) if response.status == 404 || response.status == 405 => {
            let _ = complete_pending_logout(ticket)?;
            Ok(PendingLogoutOutcome::UnsupportedLocalOnly)
        }
        Ok(response) => {
            let retry_after_unix_ms =
                pending_logout_retry_after(request.attempt_count, response.retry_after.as_deref());
            if !record_pending_logout_failure(ticket, retry_after_unix_ms)? {
                return Ok(PendingLogoutOutcome::Missing);
            }
            Ok(PendingLogoutOutcome::Retained {
                status: Some(response.status),
                retry_after_unix_ms,
            })
        }
        Err(_) => {
            let retry_after_unix_ms = pending_logout_retry_after(request.attempt_count, None);
            if !record_pending_logout_failure(ticket, retry_after_unix_ms)? {
                return Ok(PendingLogoutOutcome::Missing);
            }
            Ok(PendingLogoutOutcome::Retained {
                status: None,
                retry_after_unix_ms,
            })
        }
    }
}

pub fn retry_pending_logout_blocking(
    ticket: &PendingLogoutTicket,
) -> ResultType<PendingLogoutOutcome> {
    let request = with_main_ui_auth(|binding| Ok(binding.pending_logout_request(ticket)))?;
    let Some(request) = request else {
        return Ok(PendingLogoutOutcome::Missing);
    };
    if request.retry_after_unix_ms > unix_time_ms() {
        return Ok(PendingLogoutOutcome::Retained {
            status: None,
            retry_after_unix_ms: request.retry_after_unix_ms,
        });
    }
    let target = endpoint_under_base(&request.ticket.normalized_api_base, "api/logout")?;
    let body = logout_identity_body(&request.device_identity)?;
    let http_request =
        crate::common::StrictHttpRequest::new(crate::common::StrictHttpMethod::Post, target)
            .json_body(body)
            .timeout(std::time::Duration::from_secs(10));
    let response = crate::common::strict_http_request_one_shot_bearer_blocking(
        http_request,
        request.access_token,
    );
    match response {
        Ok(response) if (200..300).contains(&response.status) || response.status == 401 => {
            let _ = complete_pending_logout(ticket)?;
            Ok(PendingLogoutOutcome::Revoked)
        }
        Ok(response) if response.status == 404 || response.status == 405 => {
            let _ = complete_pending_logout(ticket)?;
            Ok(PendingLogoutOutcome::UnsupportedLocalOnly)
        }
        Ok(response) => {
            let retry_after_unix_ms =
                pending_logout_retry_after(request.attempt_count, response.retry_after.as_deref());
            if !record_pending_logout_failure(ticket, retry_after_unix_ms)? {
                return Ok(PendingLogoutOutcome::Missing);
            }
            Ok(PendingLogoutOutcome::Retained {
                status: Some(response.status),
                retry_after_unix_ms,
            })
        }
        Err(_) => {
            let retry_after_unix_ms = pending_logout_retry_after(request.attempt_count, None);
            if !record_pending_logout_failure(ticket, retry_after_unix_ms)? {
                return Ok(PendingLogoutOutcome::Missing);
            }
            Ok(PendingLogoutOutcome::Retained {
                status: None,
                retry_after_unix_ms,
            })
        }
    }
}

pub fn normalize_api_base(input: &str) -> ResultType<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("API base is empty");
    }
    let mut url = Url::parse(trimmed).context("API base is not a valid absolute URL")?;
    if url.scheme() != "https" && url.scheme() != "http" {
        bail!("API base must use HTTP or HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("API base must not contain user information");
    }
    if url.host().is_none() {
        bail!("API base must contain a host");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("API base must not contain a query or fragment");
    }
    if matches!(
        (url.scheme(), url.port()),
        ("https", Some(443)) | ("http", Some(80))
    ) {
        url.set_port(None)
            .map_err(|_| anyhow!("Failed to normalize API base port"))?;
    }
    let normalized_path = normalize_base_path(url.path());
    url.set_path(&normalized_path);
    let mut normalized = url.to_string();
    while normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}

fn normalize_optional_effective_api_base(input: &str) -> ResultType<Option<String>> {
    if input.trim().is_empty() {
        Ok(None)
    } else {
        normalize_api_base(input).map(Some)
    }
}

pub fn validate_strict_target(url: &str) -> ResultType<Url> {
    let parsed = Url::parse(url).context("Strict request URL is invalid")?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        bail!("Strict request URL contains forbidden components");
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if is_numeric_loopback(&parsed) => Ok(parsed),
        "http" => bail!("Strict requests reject non-loopback plaintext HTTP"),
        _ => bail!("Strict requests require HTTPS or loopback HTTP"),
    }
}

pub fn validate_target_against_base(normalized_base: &str, target: &str) -> ResultType<()> {
    let base = Url::parse(normalized_base).context("Stored API base is invalid")?;
    let target = validate_strict_target(target)?;
    if origin_tuple(&base) != origin_tuple(&target) {
        bail!("Credentialed request target does not match the authenticated origin");
    }
    let base_path = normalize_base_path(base.path());
    if base_path != "/" {
        let target_path = target.path();
        if target_path != base_path
            && !target_path
                .strip_prefix(&base_path)
                .is_some_and(|remaining| remaining.starts_with('/'))
        {
            bail!("Credentialed request target escapes the authenticated base path");
        }
    }
    Ok(())
}

pub fn redacted_url(input: &str) -> String {
    let Ok(url) = Url::parse(input) else {
        return "<invalid-url>".to_owned();
    };
    let Some(host) = url.host() else {
        return "<invalid-url>".to_owned();
    };
    let host = match host {
        Host::Ipv6(address) => format!("[{address}]"),
        Host::Ipv4(address) => address.to_string(),
        Host::Domain(domain) => domain.to_owned(),
    };
    let port = match url.port() {
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    format!("{}://{}{}/<redacted>", url.scheme(), host, port)
}

pub fn scrub_legacy_auth_mirror() {
    LocalConfig::set_option("access_token".to_owned(), String::new());
    LocalConfig::set_option("user_info".to_owned(), String::new());
}

pub fn normalize_authority_option_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

/// 返回通用配置桥永远不得读写的认证权威键。
///
/// 这里故意同时覆盖历史精确键和未来同族前缀，避免 Flutter、Sciter、
/// IPC 与 service strategy 各自维护一份会逐渐漂移的黑名单。
pub fn is_protected_auth_option(key: &str) -> bool {
    let key = normalize_authority_option_key(key);
    matches!(
        key.as_str(),
        "access_token"
            | "user_info"
            | "auth_state"
            | "auth_session"
            | "auth_epoch"
            | "auth_cursor"
            | "auth_namespace"
            | "auth_pending"
            | "cursor"
            | "pending"
            | "pending_logout"
            | "pending_logouts"
            | "native_auth_state"
            | "native_auth_cursor"
            | "native_auth_pending"
            | "address_book_cursor"
            | "credentialed_request"
            | "ui_auth_v1"
    ) || key.starts_with("auth_")
        || key.starts_with("native_auth_")
        || key.starts_with("ui_auth_")
        || key.starts_with("address_book_cursor_")
        || key.starts_with("pending_logout_")
        || key.starts_with("credentialed_request_")
}

/// 服务器解析器的四个运行期可变输入只能经 stage-and-publish 发布。
pub fn is_server_authority_option(key: &str) -> bool {
    matches!(
        normalize_authority_option_key(key).as_str(),
        "api_server" | "custom_rendezvous_server" | "relay_server" | "key"
    )
}

fn with_main_ui_auth<T>(
    operation: impl FnOnce(&mut AuthBinding) -> ResultType<T>,
) -> ResultType<T> {
    let binding = MAIN_UI_AUTH
        .get()
        .ok_or_else(|| anyhow!("Native auth binding is not initialized for the main UI"))?;
    let mut binding = binding
        .lock()
        .map_err(|_| anyhow!("Native auth binding lock is poisoned"))?;
    operation(&mut binding)
}

fn ensure_attempt_is_current(state: &NativeAuthStateV1, attempt: &AuthAttempt) -> ResultType<()> {
    if !state_attempt_is_current(state, attempt) {
        bail!("Authentication attempt is stale");
    }
    Ok(())
}

fn state_attempt_is_current(state: &NativeAuthStateV1, attempt: &AuthAttempt) -> bool {
    state.latest_attempt.as_ref().is_some_and(|current| {
        current.attempt_id == attempt.attempt_id
            && current.nonce == attempt.nonce
            && current.normalized_api_base == attempt.normalized_api_base
            && current.logout_generation == attempt.logout_generation
            && state.logout_generation == attempt.logout_generation
    })
}

fn snapshot_from_state(state: &NativeAuthStateV1) -> AuthSnapshot {
    let session = state.session.as_ref().map(|session| {
        let namespace = match state.namespaces.get(&session.cursor_key) {
            Some(namespace) => namespace.clone(),
            None => AuthNamespaceState::default(),
        };
        AuthSessionSnapshot {
            normalized_api_base: session.normalized_api_base.clone(),
            namespace: session.subject.namespace_component(),
            subject: session.subject.clone(),
            cursor_key: session.cursor_key.clone(),
            cursor: namespace.cursor,
            capability: namespace.capability,
            force_full_pending: namespace.force_full_pending,
            is_pro: namespace.pro_epoch == Some(session.epoch),
            session_epoch: session.epoch,
            session_nonce: session.nonce.clone(),
            safe_user: session.safe_user.clone(),
        }
    });
    AuthSnapshot {
        revision: state.revision,
        auth_epoch: state.auth_epoch,
        logout_generation: state.logout_generation,
        pending_logout_count: state.pending_logouts.len(),
        session,
        corrupt: false,
    }
}

fn handle_from_session(session: &NativeAuthSession) -> CredentialedRequestHandle {
    CredentialedRequestHandle {
        request_context_id: hbb_common::uuid::Uuid::new_v4().to_string(),
        normalized_api_base: session.normalized_api_base.clone(),
        namespace: session.subject.namespace_component(),
        session_epoch: session.epoch,
        session_nonce: session.nonce.clone(),
        cursor_key: session.cursor_key.clone(),
    }
}

fn state_handle_is_current(state: &NativeAuthStateV1, handle: &CredentialedRequestHandle) -> bool {
    state.session.as_ref().is_some_and(|session| {
        session.normalized_api_base == handle.normalized_api_base
            && session.subject.namespace_component() == handle.namespace
            && session.epoch == handle.session_epoch
            && session.nonce == handle.session_nonce
            && session.cursor_key == handle.cursor_key
    })
}

fn same_session_handle(
    left: &CredentialedRequestHandle,
    right: &CredentialedRequestHandle,
) -> bool {
    left.normalized_api_base == right.normalized_api_base
        && left.namespace == right.namespace
        && left.session_epoch == right.session_epoch
        && left.session_nonce == right.session_nonce
        && left.cursor_key == right.cursor_key
}

fn select_subject(user: &AuthSafeUser, access_token: &str) -> ResultType<AuthSubject> {
    if let Some(id) = user.id {
        if id == 0 || id > MAX_SAFE_INTEGER {
            bail!("Authenticated user id is outside the safe integer range");
        }
        return Ok(AuthSubject::UserId(id));
    }
    if let Some(subject) = jwt_subject(access_token) {
        return Ok(AuthSubject::JwtSub(subject));
    }
    if user.name.is_empty() || user.name.chars().any(char::is_control) {
        bail!("Authenticated username cannot be used as a namespace subject");
    }
    Ok(AuthSubject::Username(user.name.clone()))
}

fn jwt_subject(access_token: &str) -> Option<String> {
    let payload = access_token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let subject = value.get("sub")?.as_str()?.to_owned();
    if subject.is_empty()
        || subject.len() > MAX_JWT_SUBJECT_BYTES
        || subject.chars().any(char::is_control)
    {
        return None;
    }
    Some(subject)
}

fn normalize_base_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub(crate) fn endpoint_under_base(normalized_base: &str, suffix: &str) -> ResultType<String> {
    if suffix.is_empty()
        || suffix.starts_with('/')
        || suffix.contains('?')
        || suffix.contains('#')
        || suffix
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
    {
        bail!("API endpoint suffix is invalid");
    }
    let canonical_base = normalize_api_base(normalized_base)?;
    if canonical_base != normalized_base {
        bail!("Stored API base is not canonical");
    }
    let mut url = Url::parse(normalized_base).context("Stored API base is invalid")?;
    let base_path = normalize_base_path(url.path());
    let path = if base_path == "/" {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    let target = url.to_string();
    validate_target_against_base(normalized_base, &target)?;
    Ok(target)
}

fn logout_identity_body(identity: &DeviceIdentitySnapshot) -> ResultType<Vec<u8>> {
    let valid_id = !identity.id.is_empty()
        && identity.id.chars().count() <= 100
        && !identity.id.chars().any(char::is_control);
    let valid_uuid = URL_SAFE_NO_PAD
        .decode(&identity.uuid)
        .or_else(|_| hbb_common::base64::engine::general_purpose::STANDARD.decode(&identity.uuid))
        .is_ok_and(|decoded| !decoded.is_empty() && decoded.len() <= 64);
    if valid_id && valid_uuid {
        serde_json::to_vec(&serde_json::json!({
            "id": identity.id.as_str(),
            "uuid": identity.uuid.as_str(),
        }))
        .context("Failed to encode pending logout request")
    } else {
        Ok(b"{}".to_vec())
    }
}

fn pending_logout_retry_after(attempt_count: u32, retry_after: Option<&str>) -> u64 {
    let parsed_retry_seconds = retry_after
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds <= 300);
    let retry_seconds = match parsed_retry_seconds {
        Some(seconds) => seconds,
        None => {
            let shift = attempt_count.min(6);
            5u64.saturating_mul(1u64 << shift).min(300)
        }
    };
    unix_time_ms()
        .saturating_add(retry_seconds.saturating_mul(1_000))
        .min(MAX_SAFE_INTEGER)
}

fn unix_time_ms() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => match u64::try_from(duration.as_millis()) {
            Ok(value) => value,
            Err(_) => u64::MAX,
        },
        Err(_) => 0,
    }
}

fn origin_tuple(url: &Url) -> (String, String, Option<u16>) {
    let host = match url.host_str() {
        Some(host) => host.to_ascii_lowercase(),
        None => String::new(),
    };
    (
        url.scheme().to_ascii_lowercase(),
        host,
        url.port_or_known_default(),
    )
}

fn is_numeric_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustdesk-auth-binding-fault-{}",
                hbb_common::uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("应创建测试目录");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn user() -> AuthSafeUser {
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
        }
    }

    fn authenticated_binding(root: &TestRoot, api_base: &str) -> AuthBinding {
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(&root.0, b"base-transition-install")
                .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt = binding.begin_auth_attempt(api_base).expect("应开始登录");
        binding
            .commit_auth_attempt(&attempt, "token".to_owned(), user(), None)
            .expect("应提交登录");
        binding
    }

    fn empty_identity() -> DeviceIdentitySnapshot {
        DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        }
    }

    #[test]
    fn authentication_commit_does_not_persist_verifier() {
        let root = TestRoot::new();
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(root.0.as_path(), b"safe-user-install")
                .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录");
        let verifier = "issue9-verifier-sentinel";
        let mut safe_user = user();
        safe_user.verifier = verifier.to_owned();

        let snapshot = binding
            .commit_auth_attempt(&attempt, "token".to_owned(), safe_user, None)
            .expect("应提交登录");
        assert_eq!(
            snapshot
                .session
                .as_ref()
                .expect("应存在认证会话")
                .safe_user
                .verifier,
            ""
        );
        assert!(!format!("{snapshot:?}").contains(verifier));
        assert_eq!(
            binding
                .store
                .snapshot()
                .session
                .as_ref()
                .expect("应持久化认证会话")
                .safe_user
                .verifier,
            ""
        );
    }

    #[test]
    fn committed_result_becomes_stale_as_soon_as_a_new_attempt_starts() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"committed-result-owner",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt_a = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录 A");
        let opaque_a = serialize_auth_attempt(&attempt_a).expect("应序列化 attempt A");
        binding
            .commit_auth_attempt(&attempt_a, "token-a".to_owned(), user(), None)
            .expect("应提交登录 A");
        let handle_a = binding
            .credentialed_request_handle("https://example.com/api/currentUser")
            .expect("应取得 A 会话 handle");
        assert!(binding.committed_auth_attempt_result_is_current(&attempt_a, &handle_a));
        assert_eq!(
            serialize_auth_attempt(&attempt_a).expect("应再次序列化 attempt A"),
            opaque_a
        );

        let attempt_b = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录 B");
        assert!(attempt_b.attempt_id > attempt_a.attempt_id);
        assert!(!binding.committed_auth_attempt_result_is_current(&attempt_a, &handle_a));
        assert!(binding.is_auth_attempt_current(&attempt_b));
    }

    #[test]
    fn commit_and_cancel_have_deterministic_exact_linearization() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"commit-cancel-linearization",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");

        let cancel_first = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始 cancel-first attempt");
        assert!(binding
            .cancel_auth_attempt(&cancel_first)
            .expect("应取消 attempt"));
        assert!(binding
            .commit_auth_attempt(&cancel_first, "late-token".to_owned(), user(), None)
            .is_err());
        assert!(binding.snapshot().session.is_none());

        let commit_first = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始 commit-first attempt");
        binding
            .commit_auth_attempt(&commit_first, "token-a".to_owned(), user(), None)
            .expect("应提交 attempt A");
        let handle_a = binding
            .credentialed_request_handle("https://example.com/api/currentUser")
            .expect("应取得 A handle");
        assert!(binding
            .clear_auth_session_if_current(&handle_a)
            .expect("未 ACK 的 commit 应可条件回滚"));
        assert!(binding.snapshot().session.is_none());

        let attempt_a = binding
            .begin_auth_attempt("https://example.com")
            .expect("应重新开始 A");
        binding
            .commit_auth_attempt(&attempt_a, "token-a2".to_owned(), user(), None)
            .expect("应提交 A2");
        let stale_handle_a = binding
            .credentialed_request_handle("https://example.com/api/currentUser")
            .expect("应取得 A2 handle");
        let attempt_b = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始 B");
        let mut user_b = user();
        user_b.id = Some(2);
        user_b.name = "bob".to_owned();
        binding
            .commit_auth_attempt(&attempt_b, "token-b".to_owned(), user_b, None)
            .expect("应提交 B");
        assert!(!binding
            .clear_auth_session_if_current(&stale_handle_a)
            .expect("A 的回滚不得清 B"));
        assert_eq!(
            binding
                .snapshot()
                .session
                .expect("B 会话必须保留")
                .safe_user
                .name,
            "bob"
        );
    }

    #[test]
    fn commit_rolls_back_before_return_when_local_owner_is_lost() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"commit-local-owner-rollback",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录");

        assert!(binding
            .commit_auth_attempt_with_local_owner(
                &attempt,
                "token".to_owned(),
                user(),
                None,
                |_| false,
            )
            .is_err());
        assert!(binding.snapshot().session.is_none());
        assert!(binding.store.snapshot().session.is_none());
        assert!(!binding.is_auth_attempt_current(&attempt));
    }

    #[test]
    fn flutter_commit_blocks_credentialed_access_until_exact_ack() {
        let root = TestRoot::new();
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(root.0.as_path(), b"commit-ui-ack-gate")
                .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录");

        let committed = binding
            .commit_auth_attempt_with_local_owner(
                &attempt,
                "token".to_owned(),
                user(),
                None,
                |_| true,
            )
            .expect("本地 owner 应接住 committed DTO");
        assert!(committed.session.is_some());
        assert!(binding.snapshot().session.is_none());
        assert!(binding
            .credentialed_request_handle("https://example.com/api/ab")
            .is_err());

        let state = binding.store.snapshot();
        let handle = handle_from_session(state.session.as_ref().expect("durable session 应存在"));
        assert!(!binding.is_request_current(&handle));
        assert!(binding
            .credentialed_context(&handle, "https://example.com/api/ab")
            .is_err());
        assert!(!binding.acknowledge_committed_auth_attempt_result(&attempt, &handle, || false));
        assert!(binding.snapshot().session.is_none());
        assert!(binding.acknowledge_committed_auth_attempt_result(&attempt, &handle, || true));
        assert!(binding.snapshot().session.is_some());
        assert!(binding
            .credentialed_request_handle("https://example.com/api/ab")
            .is_ok());
    }

    #[test]
    fn concurrent_strict_login_claim_calls_sender_once_and_does_not_block_cancel_or_b() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"strict-login-in-flight",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt_a = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录 A");
        let send_count = std::cell::Cell::new(0_u32);

        let (stale_claim, stale_output) = claim_auth_attempt_and_send(
            &attempt_a,
            |_| false,
            || send_count.set(send_count.get() + 1),
        )
        .expect("stale claim 应 fail-closed");
        assert!(stale_output.is_none());
        assert_eq!(send_count.get(), 0);
        drop(stale_claim);

        let (claim_a, first_output) = claim_auth_attempt_and_send(
            &attempt_a,
            |_| true,
            || {
                send_count.set(send_count.get() + 1);
                let duplicate = claim_auth_attempt_and_send(
                    &attempt_a,
                    |_| true,
                    || send_count.set(send_count.get() + 1),
                );
                assert!(duplicate.is_err());
            },
        )
        .expect("首个 sender 应取得 claim");
        assert_eq!(first_output, Some(()));
        assert_eq!(send_count.get(), 1);
        drop(claim_a);

        let (retry_claim, retry_output) = claim_auth_attempt_and_send(
            &attempt_a,
            |_| true,
            || send_count.set(send_count.get() + 1),
        )
        .expect("recoverable 结束后同一 attempt 应可重试");
        assert_eq!(retry_output, Some(()));
        assert_eq!(send_count.get(), 2);
        drop(retry_claim);

        // sender 内仍持有 A 的 claim；取消和不同代次 B 不需要等待该网络 owner。
        let (claim_a, attempt_b) = claim_auth_attempt_and_send(
            &attempt_a,
            |_| true,
            || {
                send_count.set(send_count.get() + 1);
                assert!(binding
                    .cancel_auth_attempt(&attempt_a)
                    .expect("取消 A 不应被网络 claim 阻塞"));
                binding
                    .begin_auth_attempt("https://example.com")
                    .expect("应立即开始 B")
            },
        )
        .expect("A 应再次取得 claim");
        let attempt_b = attempt_b.expect("A sender 应创建 B");
        let (claim_b, b_output) = claim_auth_attempt_and_send(
            &attempt_b,
            |_| true,
            || send_count.set(send_count.get() + 1),
        )
        .expect("B 应有独立 claim");
        assert_eq!(b_output, Some(()));
        assert_eq!(send_count.get(), 4);
        drop(claim_b);
        drop(claim_a);
    }

    #[test]
    fn concurrent_strict_login_claim_is_independent_per_attempt_and_exactly_deduplicated() {
        use std::{
            sync::{
                atomic::{AtomicUsize, Ordering},
                mpsc, Arc, Barrier, Condvar, Mutex,
            },
            time::Duration,
        };

        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"strict-login-parallel-cas",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt_a = binding
            .begin_auth_attempt("https://a.example.com")
            .expect("应开始登录 A");
        let attempt_b = binding
            .begin_auth_attempt("https://b.example.com")
            .expect("应开始登录 B");

        // 两个不同 attempt 同时竞争注册表时都必须进入 sender，不能因全局 CAS 锁碰撞误拒。
        let start = Arc::new(Barrier::new(3));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let send_count = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for attempt in [attempt_a.clone(), attempt_b] {
            let start = start.clone();
            let release = release.clone();
            let send_count = send_count.clone();
            let entered_tx = entered_tx.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                claim_auth_attempt_and_send(
                    &attempt,
                    |_| true,
                    || {
                        send_count.fetch_add(1, Ordering::SeqCst);
                        entered_tx.send(()).expect("应通知 sender 已进入");
                        let (released, ready) = &*release;
                        let mut released = released.lock().expect("release 锁不应损坏");
                        while !*released {
                            released = ready.wait(released).expect("release 等待不应失败");
                        }
                    },
                )
                .map(|(claim, output)| {
                    assert_eq!(output, Some(()));
                    drop(claim);
                })
            }));
        }
        drop(entered_tx);
        start.wait();
        let first_entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let second_entered = entered_rx.recv_timeout(Duration::from_secs(5));
        {
            let (released, ready) = &*release;
            *released.lock().expect("release 锁不应损坏") = true;
            ready.notify_all();
        }
        assert!(first_entered.is_ok(), "首个 attempt 应进入 sender");
        assert!(second_entered.is_ok(), "不同 attempt 也应进入 sender");
        for worker in workers {
            worker
                .join()
                .expect("不同 attempt worker 不应 panic")
                .expect("不同 attempt 都应取得独立 claim");
        }
        assert_eq!(send_count.load(Ordering::SeqCst), 2);

        // 同一 exact attempt 并发时只允许一个 sender；另一调用不排队并立即失败。
        let start = Arc::new(Barrier::new(3));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let send_count = Arc::new(AtomicUsize::new(0));
        let (result_tx, result_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let attempt = attempt_a.clone();
            let start = start.clone();
            let release = release.clone();
            let send_count = send_count.clone();
            let result_tx = result_tx.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let result = claim_auth_attempt_and_send(
                    &attempt,
                    |_| true,
                    || {
                        send_count.fetch_add(1, Ordering::SeqCst);
                        let (released, ready) = &*release;
                        let mut released = released.lock().expect("release 锁不应损坏");
                        while !*released {
                            released = ready.wait(released).expect("release 等待不应失败");
                        }
                    },
                );
                result_tx
                    .send(result.map(|(claim, output)| {
                        assert_eq!(output, Some(()));
                        drop(claim);
                    }))
                    .expect("应返回 claim 结果");
            }));
        }
        drop(result_tx);
        start.wait();
        let duplicate = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("重复 exact attempt 应立即返回");
        assert!(duplicate.is_err(), "重复 exact attempt 必须 fail-closed");
        {
            let (released, ready) = &*release;
            *released.lock().expect("release 锁不应损坏") = true;
            ready.notify_all();
        }
        let owner = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("owner 应在释放后返回");
        assert!(owner.is_ok(), "首个 exact attempt 应取得 claim");
        for worker in workers {
            worker.join().expect("exact attempt worker 不应 panic");
        }
        assert_eq!(send_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn effective_base_change_durably_invalidates_old_session_before_publish() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com");
        let before = binding.snapshot();

        let transition = binding
            .reconcile_effective_api_base_before_publish(
                "https://a.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .expect("应先失效旧会话");

        assert!(transition.base_changed);
        assert!(transition.session_invalidated);
        assert!(transition.snapshot.session.is_none());
        assert_eq!(transition.snapshot.pending_logout_count, 1);
        assert!(transition.snapshot.auth_epoch > before.auth_epoch);
        assert!(transition.snapshot.logout_generation > before.logout_generation);
        let tickets = binding.pending_logout_tickets();
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].normalized_api_base, "https://a.example.com");
    }

    #[test]
    fn unchanged_effective_base_keeps_session_and_generation() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com/root/");
        let before = binding.snapshot();

        let transition = binding
            .reconcile_effective_api_base_before_publish(
                "https://A.EXAMPLE.com:443/root",
                "https://a.example.com/root/",
                empty_identity(),
            )
            .expect("相同有效地址不应注销");

        assert!(!transition.base_changed);
        assert!(!transition.session_invalidated);
        assert_eq!(transition.snapshot, before);
    }

    #[test]
    fn effective_base_change_durably_invalidates_inflight_login_attempt() {
        let root = TestRoot::new();
        let authority = AuthAuthorityAnchor::from_root_and_identity(
            root.0.as_path(),
            b"attempt-base-change-install",
        )
        .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://a.example.com")
            .expect("应开始 A 登录");
        let before = binding.snapshot();

        let transition = binding
            .reconcile_effective_api_base_before_publish(
                "https://a.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .expect("发布 B 前应持久化失效 A 的在途登录");

        assert!(transition.base_changed);
        assert!(!transition.session_invalidated);
        assert!(transition.snapshot.session.is_none());
        assert!(transition.snapshot.auth_epoch > before.auth_epoch);
        assert!(transition.snapshot.logout_generation > before.logout_generation);
        assert!(!binding.is_auth_attempt_current(&attempt));
        assert!(binding
            .commit_auth_attempt(&attempt, "late-a-token".to_owned(), user(), None)
            .is_err());
        assert!(binding.snapshot().session.is_none());
    }

    #[test]
    fn startup_base_mismatch_invalidates_session_even_without_runtime_change() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com");

        let transition = binding
            .reconcile_effective_api_base_before_publish(
                "https://b.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .expect("启动核对应失效来源不匹配的会话");

        assert!(!transition.base_changed);
        assert!(transition.session_invalidated);
        assert!(transition.snapshot.session.is_none());
        assert_eq!(transition.snapshot.pending_logout_count, 1);
    }

    #[test]
    fn returning_to_original_base_does_not_revive_old_session() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com");

        binding
            .reconcile_effective_api_base_before_publish(
                "https://a.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .expect("A 到 B 应注销");
        let transition = binding
            .reconcile_effective_api_base_before_publish(
                "https://b.example.com",
                "https://a.example.com",
                empty_identity(),
            )
            .expect("B 返回 A 应保持无会话");

        assert!(transition.base_changed);
        assert!(!transition.session_invalidated);
        assert!(transition.snapshot.session.is_none());
        assert_eq!(transition.snapshot.pending_logout_count, 1);
    }

    #[test]
    fn failed_logout_persist_blocks_base_publication_and_keeps_old_session() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com");
        let before = binding.snapshot();
        super::super::auth_state_store::fail_next_persist_before_replace(
            binding.authority_directory(),
        );

        assert!(binding
            .reconcile_effective_api_base_before_publish(
                "https://a.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .is_err());
        assert_eq!(binding.snapshot(), before);
    }

    #[test]
    fn address_book_completion_persist_fault_is_all_old() {
        let root = TestRoot::new();
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(root.0.as_path(), b"fault-test-install")
                .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority.clone()).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录");
        binding
            .commit_auth_attempt(&attempt, "token".to_owned(), user(), None)
            .expect("应提交登录");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建请求 handle");
        let before = binding.snapshot();

        super::super::auth_state_store::fail_next_persist_before_replace(
            binding.authority_directory(),
        );
        assert!(binding
            .complete_address_book_pull(&handle, 0, 9, false)
            .is_err());
        assert_eq!(binding.snapshot(), before);

        drop(binding);
        let reopened = AuthBinding::open(authority).expect("应重新打开 binding");
        assert_eq!(reopened.snapshot(), before);
    }

    fn one_personal_hash(peer_id: &str, value: &[u8]) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([(peer_id.to_owned(), value.to_vec())])
    }

    fn issue_and_commit_personal_hash(
        binding: &mut AuthBinding,
        handle: &CredentialedRequestHandle,
        source: PersonalHashSource,
        hashes: BTreeMap<String, Vec<u8>>,
    ) -> bool {
        let request_fence = binding
            .personal_hash_request_fence(handle)
            .expect("应捕获 personal hash 请求栅栏");
        let receipt = binding
            .issue_personal_hash_receipt(handle, request_fence, source, hashes)
            .expect("应签发 personal hash receipt")
            .expect("当前请求应获得 personal hash receipt");
        binding
            .commit_personal_hash_receipt(handle, &receipt)
            .expect("应消费 personal hash receipt")
    }

    #[test]
    fn personal_hash_allowlist_is_generation_bound_and_empty_replace_removes_deleted_peer() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建请求 handle");
        let stale_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获旧请求栅栏");

        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"legacy-hash"),
        ));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应先确认 legacy 能力"));
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"legacy-hash".to_vec())
        );

        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            BTreeMap::new(),
        ));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"old-generation"),
        ));
        assert!(binding
            .clear_auth_session_if_current(&handle)
            .expect("应清除当前会话"));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("新代应可重新登录");
        binding
            .commit_auth_attempt(&attempt, "new-token".to_owned(), user(), None)
            .expect("应提交新代登录");
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(binding
            .issue_personal_hash_receipt(
                &handle,
                stale_fence,
                PersonalHashSource::LegacyPersonal,
                one_personal_hash("100001", b"stale"),
            )
            .expect("旧 handle 不应导致错误")
            .is_none());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
    }

    #[test]
    fn personal_hash_receipt_is_request_bound_and_one_shot() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let issuing_handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建签发请求 handle");
        let other_handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建同代另一请求 handle");
        binding
            .set_address_book_capability(&issuing_handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        let request_fence = binding
            .personal_hash_request_fence(&issuing_handle)
            .expect("应捕获签发请求栅栏");

        let receipt = binding
            .issue_personal_hash_receipt(
                &issuing_handle,
                request_fence,
                PersonalHashSource::LegacyPersonal,
                one_personal_hash("100001", b"request-bound"),
            )
            .expect("应签发 receipt")
            .expect("当前请求应获得 receipt");
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(binding
            .commit_personal_hash_receipt(&other_handle, &receipt)
            .is_err());
        assert!(binding
            .commit_personal_hash_receipt(&issuing_handle, &receipt)
            .is_err());
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        let request_fence = binding
            .personal_hash_request_fence(&issuing_handle)
            .expect("应捕获重新签发请求栅栏");
        let receipt = binding
            .issue_personal_hash_receipt(
                &issuing_handle,
                request_fence,
                PersonalHashSource::LegacyPersonal,
                one_personal_hash("100001", b"one-shot"),
            )
            .expect("应重新签发 receipt")
            .expect("当前请求应获得 receipt");
        assert!(binding
            .commit_personal_hash_receipt(&issuing_handle, &receipt)
            .expect("首次消费应成功"));
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"one-shot".to_vec())
        );
        assert!(binding
            .commit_personal_hash_receipt(&issuing_handle, &receipt)
            .is_err());
    }

    #[test]
    fn personal_hash_request_start_fence_blocks_late_response_and_stale_error_after_mutation() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建 legacy 请求 handle");
        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"before-mutation"),
        ));

        let binding = std::sync::Arc::new(std::sync::Mutex::new(binding));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let reader_binding = binding.clone();
        let reader_barrier = barrier.clone();
        let reader_handle = handle.clone();
        let reader = std::thread::spawn(move || {
            let request_fence = {
                let binding = reader_binding.lock().unwrap();
                let fence = binding
                    .personal_hash_request_fence(&reader_handle)
                    .expect("读请求应捕获开始栅栏");
                assert!(binding.personal_hash_response_is_current(&reader_handle, fence));
                fence
            };
            // 请求已发出并阻塞在响应前，让 mutation 完整开始并结束。
            reader_barrier.wait();
            reader_barrier.wait();

            let mut binding = reader_binding.lock().unwrap();
            assert!(binding
                .issue_personal_hash_receipt(
                    &reader_handle,
                    request_fence,
                    PersonalHashSource::LegacyPersonal,
                    one_personal_hash("100001", b"stale-response"),
                )
                .expect("迟到响应应被安全忽略")
                .is_none());
            // 模拟 observer 初次 current 检查后发生 mutation，旧错误路径不得清新状态。
            assert!(!binding
                .invalidate_personal_hash_provenance_if_current(&reader_handle, request_fence,)
                .expect("旧错误响应应被安全忽略"));
        });

        barrier.wait();
        {
            let mut binding = binding.lock().unwrap();
            assert!(binding
                .begin_personal_hash_mutation_if_current(&handle, None)
                .expect("应开始 personal mutation"));
            assert_eq!(binding.personal_hash_for_peer("100001"), None);
            assert!(binding
                .finish_personal_hash_mutation_if_current(&handle)
                .expect("应结束 personal mutation"));
            assert!(issue_and_commit_personal_hash(
                &mut binding,
                &handle,
                PersonalHashSource::LegacyPersonal,
                one_personal_hash("100001", b"after-mutation"),
            ));
        }
        barrier.wait();
        reader.join().expect("读线程不应失败");

        assert_eq!(
            binding.lock().unwrap().personal_hash_for_peer("100001"),
            Some(b"after-mutation".to_vec())
        );
    }

    #[test]
    fn personal_hash_capability_transition_preserves_inflight_mutation_barrier() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建 legacy 请求 handle");
        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"before-transition"),
        ));

        assert!(binding
            .begin_personal_hash_mutation_if_current(&handle, None)
            .expect("应开始阻塞中的 mutation"));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        assert!(binding
            .set_address_book_capability(&handle, AddressBookCapability::Unknown, true)
            .expect("同代 capability 失效应成功"));
        let after_capability_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获 capability 后栅栏");
        assert!(!binding.personal_hash_response_is_current(&handle, after_capability_fence));
        assert!(binding
            .issue_personal_hash_receipt(
                &handle,
                after_capability_fence,
                PersonalHashSource::LegacyPersonal,
                one_personal_hash("100001", b"must-not-publish"),
            )
            .expect("mutation 阻塞期间响应应被忽略")
            .is_none());

        assert!(binding
            .complete_address_book_pull(&handle, 0, 1, false)
            .expect("同代 v2 completion 应成功"));
        let after_completion_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获 completion 后栅栏");
        assert!(!binding.personal_hash_response_is_current(&handle, after_completion_fence));
        assert!(binding
            .finish_personal_hash_mutation_if_current(&handle)
            .expect("capability/v2 清理不得破坏 begin/finish 配对"));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
    }

    #[test]
    fn personal_hash_connection_capability_is_bound_to_repull_mutation_v2_and_auth_generation() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建 legacy 请求 handle");
        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"same-hash"),
        ));
        let before_repull = binding
            .personal_hash_connection_capability("100001", b"same-hash")
            .expect("应签发连接能力");
        assert!(binding.personal_hash_connection_capability_is_current(&before_repull));
        let before_repull_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获重拉前栅栏");

        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"same-hash"),
        ));
        assert_ne!(
            binding
                .personal_hash_request_fence(&handle)
                .expect("应捕获重拉后栅栏"),
            before_repull_fence
        );
        assert!(!binding.personal_hash_connection_capability_is_current(&before_repull));
        let before_mutation = binding
            .personal_hash_connection_capability("100001", b"same-hash")
            .expect("重拉后应签发新连接能力");

        assert!(binding
            .begin_personal_hash_mutation_if_current(&handle, None)
            .expect("应开始 mutation"));
        assert!(!binding.personal_hash_connection_capability_is_current(&before_mutation));
        assert!(binding
            .finish_personal_hash_mutation_if_current(&handle)
            .expect("应结束 mutation"));

        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"same-hash"),
        ));
        let before_v2 = binding
            .personal_hash_connection_capability("100001", b"same-hash")
            .expect("v2 前应签发连接能力");
        assert!(binding
            .complete_address_book_pull(&handle, 0, 1, false)
            .expect("应完成 v2 拉取"));
        assert!(!binding.personal_hash_connection_capability_is_current(&before_v2));

        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("测试中应重新确认 legacy");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"same-hash"),
        ));
        let before_logout = binding
            .personal_hash_connection_capability("100001", b"same-hash")
            .expect("logout 前应签发连接能力");
        assert!(binding
            .clear_auth_session_if_current(&handle)
            .expect("应清除 A 会话"));
        assert!(!binding.personal_hash_connection_capability_is_current(&before_logout));

        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始 B 登录");
        let mut user_b = user();
        user_b.id = Some(2);
        user_b.name = "bob".to_owned();
        binding
            .commit_auth_attempt(&attempt, "token-b".to_owned(), user_b, None)
            .expect("应提交 B 登录");
        let handle_b = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建 B 请求 handle");
        binding
            .set_address_book_capability(&handle_b, AddressBookCapability::Legacy, false)
            .expect("应确认 B legacy 能力");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle_b,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"same-hash"),
        ));
        assert!(!binding.personal_hash_connection_capability_is_current(&before_logout));
    }

    #[test]
    fn commercial_personal_pages_accept_same_session_handle_and_clear_retains_guid() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let discovery_handle = binding
            .credentialed_request_handle("https://example.com/api/ab/personal")
            .expect("应创建 personal guid 请求 handle");
        let discovery_fence = binding
            .personal_hash_request_fence(&discovery_handle)
            .expect("应捕获 discovery 请求栅栏");
        assert!(binding
            .register_commercial_personal_guid(
                &discovery_handle,
                discovery_fence,
                "personal-guid".to_owned(),
            )
            .expect("应注册 personal guid"));

        let page_handle = binding
            .credentialed_request_handle("https://example.com/api/ab/peers")
            .expect("应创建同代分页请求 handle");
        let page_fence = binding
            .personal_hash_request_fence(&page_handle)
            .expect("应捕获分页请求栅栏");
        assert!(binding.is_current_commercial_personal_guid(
            &page_handle,
            page_fence,
            "personal-guid"
        ));
        assert!(!binding.is_current_commercial_personal_guid(
            &page_handle,
            page_fence,
            "shared-guid"
        ));
        assert!(binding
            .observe_commercial_personal_hash_page(
                &page_handle,
                page_fence,
                "shared-guid",
                1,
                100,
                1,
                vec![("shared-only".to_owned(), Some(b"forbidden".to_vec()))],
            )
            .expect("共享地址簿分页应被忽略")
            .is_none());

        assert!(binding
            .observe_commercial_personal_hash_page(
                &page_handle,
                page_fence,
                "personal-guid",
                1,
                2,
                3,
                vec![
                    ("100001".to_owned(), Some(b"hash-a".to_vec())),
                    ("100002".to_owned(), None),
                ],
            )
            .expect("第一页应被接受")
            .is_none());
        let receipt = binding
            .observe_commercial_personal_hash_page(
                &page_handle,
                page_fence,
                "personal-guid",
                2,
                2,
                3,
                vec![("100003".to_owned(), Some(b"hash-c".to_vec()))],
            )
            .expect("末页应被接受")
            .expect("完整分页应签发 receipt");
        assert!(binding
            .commit_personal_hash_receipt(&page_handle, &receipt)
            .expect("应消费商业 personal receipt"));
        binding
            .set_address_book_capability(
                &page_handle,
                AddressBookCapability::CommercialMulti,
                false,
            )
            .expect("应确认 commercial 能力");
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"hash-a".to_vec())
        );
        assert_eq!(binding.personal_hash_for_peer("100002"), None);

        let repull_handle = binding
            .credentialed_request_handle("https://example.com/api/ab/peers")
            .expect("应创建同代重拉请求 handle");
        assert!(binding
            .clear_personal_hash_allowlist_if_current(&repull_handle)
            .expect("应清空 personal hash 表"));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        let repull_fence = binding
            .personal_hash_request_fence(&repull_handle)
            .expect("应捕获重拉请求栅栏");
        assert!(binding.is_current_commercial_personal_guid(
            &repull_handle,
            repull_fence,
            "personal-guid"
        ));
        let empty_receipt = binding
            .observe_commercial_personal_hash_page(
                &repull_handle,
                repull_fence,
                "personal-guid",
                1,
                100,
                0,
                Vec::new(),
            )
            .expect("空商业 personal 完整响应应被接受")
            .expect("空响应也应签发 receipt");
        assert!(binding
            .commit_personal_hash_receipt(&repull_handle, &empty_receipt)
            .expect("应提交空表"));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        let provenance_fence = binding
            .personal_hash_request_fence(&repull_handle)
            .expect("应捕获来源失效前栅栏");
        assert!(binding
            .invalidate_personal_hash_provenance_if_current(&repull_handle, provenance_fence)
            .expect("应失效 personal hash 来源"));
        let invalidated_fence = binding
            .personal_hash_request_fence(&repull_handle)
            .expect("应捕获失效后的栅栏");
        assert!(!binding.is_current_commercial_personal_guid(
            &repull_handle,
            invalidated_fence,
            "personal-guid"
        ));
    }

    #[test]
    fn personal_hash_commercial_pages_and_multiple_mutations_share_one_safe_fence() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab/peers")
            .expect("应创建 commercial 请求 handle");
        let discovery_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获 discovery 栅栏");
        assert!(
            binding
                .register_commercial_personal_guid(
                    &handle,
                    discovery_fence,
                    "personal-guid".to_owned(),
                )
                .expect("应登记 personal GUID")
        );
        let stale_page_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获旧分页栅栏");
        assert!(binding
            .observe_commercial_personal_hash_page(
                &handle,
                stale_page_fence,
                "personal-guid",
                1,
                1,
                2,
                vec![("100001".to_owned(), Some(b"page-one".to_vec()))],
            )
            .expect("第一页应进入 accumulator")
            .is_none());

        assert!(binding
            .begin_personal_hash_mutation_if_current(&handle, Some("personal-guid"))
            .expect("第一个 personal mutation 应开始"));
        assert!(!binding
            .begin_personal_hash_mutation_if_current(&handle, Some("shared-guid"))
            .expect("shared GUID 不应伪装成已登记 personal"));
        // strict transport 对不匹配 GUID 走该保守分支，以兼容 shared 编辑并清除旧 personal 表。
        assert!(binding
            .begin_personal_hash_mutation_if_current(&handle, None)
            .expect("shared mutation 应按潜在 personal 保守建立栅栏"));
        let during_mutations_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获并发 mutation 栅栏");
        assert!(!binding.personal_hash_response_is_current(&handle, during_mutations_fence));
        assert_eq!(binding.personal_hash_for_peer("100001"), None);

        assert!(binding
            .finish_personal_hash_mutation_if_current(&handle)
            .expect("第一个 mutation 应完成"));
        assert!(!binding.personal_hash_response_is_current(
            &handle,
            binding
                .personal_hash_request_fence(&handle)
                .expect("应捕获仍有 pending 的栅栏")
        ));
        assert!(binding
            .finish_personal_hash_mutation_if_current(&handle)
            .expect("第二个 mutation 应完成"));
        assert!(binding
            .observe_commercial_personal_hash_page(
                &handle,
                stale_page_fence,
                "personal-guid",
                2,
                1,
                2,
                vec![("100002".to_owned(), Some(b"stale-page-two".to_vec()))],
            )
            .expect("迟到末页应被安全忽略")
            .is_none());

        let fresh_page_fence = binding
            .personal_hash_request_fence(&handle)
            .expect("应捕获新完整拉取栅栏");
        let receipt = binding
            .observe_commercial_personal_hash_page(
                &handle,
                fresh_page_fence,
                "personal-guid",
                1,
                1,
                1,
                vec![("100001".to_owned(), Some(b"fresh-page".to_vec()))],
            )
            .expect("新完整拉取应成功")
            .expect("新完整拉取应签发 receipt");
        assert!(binding
            .commit_personal_hash_receipt(&handle, &receipt)
            .expect("新 receipt 应可提交"));
        binding
            .set_address_book_capability(&handle, AddressBookCapability::CommercialMulti, false)
            .expect("应确认 commercial 能力");
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"fresh-page".to_vec())
        );
    }

    #[test]
    fn issue9_v2_and_capability_transition_never_exposes_mismatched_personal_hash() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://example.com");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建请求 handle");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("same-id", b"legacy-lifecycle"),
        ));
        assert!(binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力"));
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::CommercialPersonal,
            one_personal_hash("same-id", b"commercial-lifecycle"),
        ));
        assert_eq!(binding.personal_hash_for_peer("same-id"), None);
        assert!(binding
            .set_address_book_capability(&handle, AddressBookCapability::CommercialMulti, false,)
            .expect("确认 commercial 后才可激活匹配来源"));
        assert_eq!(
            binding.personal_hash_for_peer("same-id"),
            Some(b"commercial-lifecycle".to_vec())
        );

        assert!(binding
            .complete_address_book_pull(&handle, 0, 1, false)
            .expect("应确认 v2 并提交 cursor"));
        assert_eq!(binding.personal_hash_for_peer("same-id"), None);
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("same-id", b"must-not-return"),
        ));
        assert_eq!(binding.personal_hash_for_peer("same-id"), None);
    }

    #[test]
    fn personal_hash_allowlist_is_process_memory_only_and_not_restored() {
        let root = TestRoot::new();
        let authority =
            AuthAuthorityAnchor::from_root_and_identity(root.0.as_path(), b"hash-restart-install")
                .expect("应创建 authority");
        let mut binding = AuthBinding::open(authority.clone()).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com")
            .expect("应开始登录");
        binding
            .commit_auth_attempt(&attempt, "token".to_owned(), user(), None)
            .expect("应提交登录");
        let handle = binding
            .credentialed_request_handle("https://example.com/api/ab")
            .expect("应创建请求 handle");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::CommercialPersonal,
            one_personal_hash("cached-id", b"memory-only"),
        ));
        binding
            .set_address_book_capability(&handle, AddressBookCapability::CommercialMulti, false)
            .expect("应确认 commercial 能力");
        assert_eq!(
            binding.personal_hash_for_peer("cached-id"),
            Some(b"memory-only".to_vec())
        );

        drop(binding);
        let reopened = AuthBinding::open(authority).expect("应模拟新进程打开同一认证状态");
        assert!(reopened.snapshot().session.is_some());
        assert_eq!(reopened.personal_hash_for_peer("cached-id"), None);
    }

    #[test]
    fn personal_hash_allowlist_is_cleared_before_origin_change_is_published() {
        let root = TestRoot::new();
        let mut binding = authenticated_binding(&root, "https://a.example.com");
        let handle = binding
            .credentialed_request_handle("https://a.example.com/api/ab")
            .expect("应创建请求 handle");
        assert!(issue_and_commit_personal_hash(
            &mut binding,
            &handle,
            PersonalHashSource::LegacyPersonal,
            one_personal_hash("100001", b"origin-a"),
        ));
        binding
            .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
            .expect("应确认 legacy 能力");
        assert_eq!(
            binding.personal_hash_for_peer("100001"),
            Some(b"origin-a".to_vec())
        );

        binding
            .reconcile_effective_api_base_before_publish(
                "https://a.example.com",
                "https://b.example.com",
                empty_identity(),
            )
            .expect("发布 B 前应持久化失效 A");
        assert_eq!(binding.personal_hash_for_peer("100001"), None);
        assert!(!binding
            .clear_personal_hash_allowlist_if_current(&handle)
            .expect("旧请求应被安全忽略"));
    }

    #[test]
    fn native_process_role_cannot_be_promoted_by_dart_label() {
        assert_eq!(
            classify_process_role_from_args(["rustdesk", "--connect", "peer"]),
            TrustedProcessRole::NonUi
        );
        assert_eq!(
            classify_process_role_from_args(["rustdesk", "--cm"]),
            TrustedProcessRole::NonUi
        );
        assert_eq!(
            classify_process_role_from_args(["rustdesk", "--service"]),
            TrustedProcessRole::NonUi
        );
        assert_eq!(
            classify_process_role_from_args(["rustdesk", "--install"]),
            TrustedProcessRole::NonUi
        );
        assert_eq!(
            classify_process_role_from_args(["rustdesk"]),
            TrustedProcessRole::MainUi
        );
        assert_eq!(
            classify_process_role_from_args(["rustdesk", "--no-server"]),
            TrustedProcessRole::MainUi
        );
    }

    #[test]
    fn authority_option_predicate_normalizes_all_bridge_spellings() {
        for key in [
            "ACCESS_TOKEN",
            "access-token",
            " Auth-State-Session ",
            "native-auth-cursor",
            "address-book-cursor-user",
            "pending-logout-ticket",
            "ui-auth-v1",
        ] {
            assert!(is_protected_auth_option(key), "{key} 应受保护");
        }
        for key in [
            "API-SERVER",
            "custom-rendezvous-server",
            "relay_server",
            " key ",
        ] {
            assert!(is_server_authority_option(key), "{key} 应由专用发布器处理");
        }
        assert!(!is_protected_auth_option("theme"));
        assert!(!is_server_authority_option("theme"));
    }
}
