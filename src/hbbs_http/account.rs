use super::{
    auth_binding::{self, AuthAttempt, AuthSafeUser, CredentialedRequestHandle},
    HbbHttpResponse,
};
use crate::common::{
    strict_http_request_no_bearer_blocking, RequestSecurityClass, StrictHttpMethod,
    StrictHttpRequest,
};
use hbb_common::{log, ResultType};
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use url::{Host, Url};

lazy_static::lazy_static! {
    static ref OIDC_SESSION: Arc<RwLock<OidcSession>> = Arc::new(RwLock::new(OidcSession::new()));
    /// 串行化“停止旧任务、创建原生尝试、绑定新任务”，避免并发启动顺序反转。
    static ref OIDC_START_MUTEX: Mutex<()> = Mutex::new(());
}

const QUERY_INTERVAL_SECS: f32 = 1.0;
const QUERY_TIMEOUT_SECS: u64 = 60 * 3;

const REQUESTING_ACCOUNT_AUTH: &str = "Requesting account auth";
const WAITING_ACCOUNT_AUTH: &str = "Waiting account auth";
const LOGIN_ACCOUNT_AUTH: &str = "Login account auth";

#[derive(Deserialize, Clone)]
pub struct OidcAuthUrl {
    code: String,
    url: Url,
}

impl std::fmt::Debug for OidcAuthUrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcAuthUrl")
            .field("code", &"<redacted>")
            .field("url", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct DeviceInfo {
    /// 操作系统，例如 Linux、Windows、Android。
    #[serde(default)]
    pub os: String,

    /// 设备类型：`browser` 或 `client`。
    #[serde(default)]
    pub r#type: String,

    /// RustDesk 客户端上报设备名；
    /// 浏览器上报名称和版本。
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitelistItem {
    data: String, // IP 或设备 UUID
    info: DeviceInfo,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserInfo {
    #[serde(default, flatten)]
    pub settings: UserSettings,
    #[serde(default)]
    pub login_device_whitelist: Vec<WhitelistItem>,
    #[serde(default)]
    pub other: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSettings {
    #[serde(default)]
    pub email_verification: bool,
    #[serde(default)]
    pub email_alarm_notification: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
pub enum UserStatus {
    Disabled = 0,
    #[default]
    Normal = 1,
    Unverified = -1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPayload {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub status: UserStatus,
    #[serde(default)]
    pub info: UserInfo,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub third_auth_type: Option<String>,
    #[serde(default, skip_serializing)]
    pub verifier: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthBody {
    #[serde(skip_serializing)]
    pub access_token: String,
    pub r#type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tfa_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,
    pub user: UserPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_api_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_nonce: Option<String>,
    /// 非成功 OIDC 结果所属的原生登录尝试；Dart 只能据此请求原生侧复验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_attempt: Option<String>,
}

impl std::fmt::Debug for AuthBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthBody")
            .field("access_token", &"<redacted>")
            .field("type", &self.r#type)
            .field("tfa_type", &self.tfa_type)
            .field("secret", &"<redacted>")
            .field("user", &"<redacted>")
            .field("normalized_api_base", &"<redacted>")
            .field("namespace", &self.namespace)
            .field("cursor_key", &self.cursor_key)
            .field("session_epoch", &self.session_epoch)
            .field("session_nonce", &self.session_nonce)
            .field("native_attempt", &"<redacted>")
            .finish()
    }
}

fn sanitize_auth_body_user_for_ui(auth_body: &mut AuthBody) {
    auth_body.user.verifier.clear();
    auth_body.user.info = UserInfo::default();
    auth_body.user.third_auth_type = None;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedAuthGeneration {
    normalized_api_base: String,
    namespace: String,
    cursor_key: String,
    session_epoch: u64,
    session_nonce: String,
}

impl CommittedAuthGeneration {
    fn from_session(session: &auth_binding::AuthSessionSnapshot) -> Self {
        Self {
            normalized_api_base: session.normalized_api_base.clone(),
            namespace: session.namespace.clone(),
            cursor_key: session.cursor_key.clone(),
            session_epoch: session.session_epoch,
            session_nonce: session.session_nonce.clone(),
        }
    }

    fn request_handle(&self) -> CredentialedRequestHandle {
        CredentialedRequestHandle {
            request_context_id: "oidc-result-provenance".to_owned(),
            normalized_api_base: self.normalized_api_base.clone(),
            namespace: self.namespace.clone(),
            session_epoch: self.session_epoch,
            session_nonce: self.session_nonce.clone(),
            cursor_key: self.cursor_key.clone(),
        }
    }
}

pub struct OidcSession {
    task_counter: u64,
    active_task_id: Option<u64>,
    result_task_id: Option<u64>,
    task_cancelled: bool,
    state_msg: &'static str,
    failed_msg: String,
    code_url: Option<OidcAuthUrl>,
    auth_body: Option<AuthBody>,
    committed_generation: Option<CommittedAuthGeneration>,
    unacked_committed: Option<(AuthAttempt, CommittedAuthGeneration)>,
    result_origin_attempt: Option<AuthAttempt>,
    result_origin_opaque: Option<String>,
    task_attempt: Option<AuthAttempt>,
    keep_querying: bool,
    running: bool,
    query_timeout: Duration,
}

#[derive(Clone, Serialize)]
pub struct AuthResult {
    pub state_msg: String,
    pub failed_msg: String,
    pub url: Option<String>,
    pub auth_body: Option<AuthBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_attempt: Option<String>,
}

impl OidcSession {
    fn new() -> Self {
        Self {
            task_counter: 0,
            active_task_id: None,
            result_task_id: None,
            task_cancelled: false,
            state_msg: REQUESTING_ACCOUNT_AUTH,
            failed_msg: "".to_owned(),
            code_url: None,
            auth_body: None,
            committed_generation: None,
            unacked_committed: None,
            result_origin_attempt: None,
            result_origin_opaque: None,
            task_attempt: None,
            keep_querying: false,
            running: false,
            query_timeout: Duration::from_secs(QUERY_TIMEOUT_SECS),
        }
    }

    fn auth(
        api_server: &str,
        op: &str,
        id: &str,
        uuid: &str,
    ) -> ResultType<HbbHttpResponse<OidcAuthUrl>> {
        let body = serde_json::json!({
            "op": op,
            "id": id,
            "uuid": uuid,
            "deviceInfo": crate::ui_interface::get_login_device_info(),
        })
        .to_string();
        let url = auth_binding::endpoint_under_base(api_server, "api/oidc/auth")?;
        let response = strict_http_request_no_bearer_blocking(
            RequestSecurityClass::LoginStrict,
            StrictHttpRequest::new(StrictHttpMethod::Post, url)
                .json_body(body)
                .timeout(Duration::from_secs(10)),
        )?;
        let response = response.ensure_success()?;
        HbbHttpResponse::parse(&response.body)
    }

    fn query(
        api_server: &str,
        code: &str,
        id: &str,
        uuid: &str,
    ) -> ResultType<HbbHttpResponse<AuthBody>> {
        let mut url = Url::parse(&auth_binding::endpoint_under_base(
            api_server,
            "api/oidc/auth-query",
        )?)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("code", code);
            query.append_pair("id", id);
            query.append_pair("uuid", uuid);
        }
        let response = strict_http_request_no_bearer_blocking(
            RequestSecurityClass::LoginStrict,
            StrictHttpRequest::new(StrictHttpMethod::Get, url.to_string())
                .timeout(Duration::from_secs(10)),
        )?;
        let response = response.ensure_success()?;
        HbbHttpResponse::parse(&response.body)
    }

    fn reset_visible_result(&mut self) {
        self.state_msg = REQUESTING_ACCOUNT_AUTH;
        self.failed_msg = "".to_owned();
        self.code_url = None;
        self.auth_body = None;
        self.committed_generation = None;
        self.result_origin_attempt = None;
        self.result_origin_opaque = None;
        self.result_task_id = None;
    }

    fn before_task(&mut self) -> ResultType<u64> {
        if self.running {
            hbb_common::bail!("OIDC task is already running");
        }
        if self.unacked_committed.is_some() {
            hbb_common::bail!("OIDC committed result must be acknowledged or cancelled");
        }
        self.task_counter = self
            .task_counter
            .checked_add(1)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("OIDC task generation is exhausted"))?;
        let task_id = self.task_counter;
        self.reset_visible_result();
        self.active_task_id = Some(task_id);
        self.task_cancelled = false;
        self.task_attempt = None;
        self.keep_querying = true;
        self.running = true;
        Ok(task_id)
    }

    fn bind_attempt(&mut self, task_id: u64, attempt: &AuthAttempt) -> ResultType<bool> {
        if self.active_task_id != Some(task_id)
            || !self.running
            || self.task_cancelled
            || self.task_attempt.is_some()
        {
            return Ok(false);
        }
        let opaque_attempt = auth_binding::serialize_auth_attempt(attempt)?;
        self.task_attempt = Some(attempt.clone());
        self.result_task_id = Some(task_id);
        self.result_origin_attempt = Some(attempt.clone());
        self.result_origin_opaque = Some(opaque_attempt);
        Ok(true)
    }

    fn owns_task(&self, task_id: u64) -> bool {
        self.active_task_id == Some(task_id)
    }

    fn owns_attempt(&self, task_id: u64, attempt: &AuthAttempt) -> bool {
        self.owns_task(task_id)
            && self.running
            && !self.task_cancelled
            && self.task_attempt.as_ref() == Some(attempt)
    }

    fn after_task(&mut self, task_id: u64, attempt: &AuthAttempt) -> bool {
        if !self.running || !self.owns_task(task_id) || self.task_attempt.as_ref() != Some(attempt)
        {
            return false;
        }
        self.running = false;
        self.keep_querying = false;
        true
    }

    fn after_unbound_task(&mut self, task_id: u64) -> bool {
        if !self.running || !self.owns_task(task_id) || self.task_attempt.is_some() {
            return false;
        }
        self.running = false;
        self.keep_querying = false;
        true
    }

    fn sleep(secs: f32) {
        std::thread::sleep(std::time::Duration::from_secs_f32(secs));
    }

    fn auth_url_scheme_is_allowed(url: &Url) -> bool {
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return false;
        }
        match (url.scheme(), url.host()) {
            ("https", Some(_)) => true,
            ("http", Some(Host::Domain(domain))) => domain.eq_ignore_ascii_case("localhost"),
            ("http", Some(Host::Ipv4(address))) => address.is_loopback(),
            ("http", Some(Host::Ipv6(address))) => address.is_loopback(),
            _ => false,
        }
    }

    fn send_network_if_current_with<T>(
        task_id: u64,
        attempt: &AuthAttempt,
        attempt_is_current: impl Fn(&AuthAttempt) -> bool,
        sender: impl FnOnce() -> T,
    ) -> Option<T> {
        {
            let session = OIDC_SESSION.read().unwrap();
            if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
                return None;
            }
        }
        if !attempt_is_current(attempt) {
            return None;
        }
        let session = OIDC_SESSION.read().unwrap();
        if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
            return None;
        }
        drop(session);
        Some(sender())
    }

    fn task_attempt_is_current(task_id: u64, attempt: &AuthAttempt) -> bool {
        if !Self::local_task_attempt_is_current(task_id, attempt) {
            return false;
        }
        if !auth_binding::is_auth_attempt_current(attempt) {
            return false;
        }
        Self::local_task_attempt_is_current(task_id, attempt)
    }

    fn local_task_attempt_is_current(task_id: u64, attempt: &AuthAttempt) -> bool {
        let session = OIDC_SESSION.read().unwrap();
        session.owns_attempt(task_id, attempt) && session.keep_querying
    }

    /// 新 begin/cancel 持有顺序锁并等待旧 worker 退出时，worker 不得反向等待同一锁。
    fn lock_start_if_task_current(
        task_id: u64,
        attempt: &AuthAttempt,
    ) -> ResultType<Option<std::sync::MutexGuard<'static, ()>>> {
        loop {
            match OIDC_START_MUTEX.try_lock() {
                Ok(guard) => {
                    return Ok(Self::task_attempt_is_current(task_id, attempt).then_some(guard));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if !Self::local_task_attempt_is_current(task_id, attempt) {
                        return Ok(None);
                    }
                    std::thread::yield_now();
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    hbb_common::bail!("OIDC 启动锁不可用");
                }
            }
        }
    }

    fn publish_failure_if_current(
        task_id: u64,
        attempt: &AuthAttempt,
        state_msg: &'static str,
        failed_msg: &'static str,
    ) -> bool {
        auth_binding::with_current_auth_attempt(attempt, || {
            let mut session = OIDC_SESSION.write().unwrap();
            if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
                return false;
            }
            session.state_msg = state_msg;
            session.failed_msg = failed_msg.to_owned();
            session.code_url = None;
            session.auth_body = None;
            session.committed_generation = None;
            session.result_task_id = Some(task_id);
            session.result_origin_attempt = Some(attempt.clone());
            true
        })
        .unwrap_or(false)
    }

    fn publish_code_url_if_current(
        task_id: u64,
        attempt: &AuthAttempt,
        code_url: OidcAuthUrl,
    ) -> bool {
        auth_binding::with_current_auth_attempt(attempt, || {
            let mut session = OIDC_SESSION.write().unwrap();
            if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
                return false;
            }
            session.state_msg = WAITING_ACCOUNT_AUTH;
            session.failed_msg.clear();
            session.code_url = Some(code_url);
            session.auth_body = None;
            session.committed_generation = None;
            session.result_task_id = Some(task_id);
            session.result_origin_attempt = Some(attempt.clone());
            true
        })
        .unwrap_or(false)
    }

    fn publish_challenge_if_current(
        task_id: u64,
        attempt: &AuthAttempt,
        mut auth_body: AuthBody,
    ) -> bool {
        let Ok(opaque_attempt) = auth_binding::serialize_auth_attempt(attempt) else {
            return false;
        };
        auth_body.access_token.clear();
        auth_body.normalized_api_base = None;
        auth_body.namespace = None;
        auth_body.cursor_key = None;
        auth_body.session_epoch = None;
        auth_body.session_nonce = None;
        auth_body.native_attempt = Some(opaque_attempt);
        sanitize_auth_body_user_for_ui(&mut auth_body);

        auth_binding::with_current_auth_attempt(attempt, || {
            let mut session = OIDC_SESSION.write().unwrap();
            if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
                return false;
            }
            session.state_msg = LOGIN_ACCOUNT_AUTH;
            session.failed_msg.clear();
            session.code_url = None;
            session.auth_body = Some(auth_body);
            session.committed_generation = None;
            session.result_task_id = Some(task_id);
            session.result_origin_attempt = Some(attempt.clone());
            true
        })
        .unwrap_or(false)
    }

    /// 仅在 auth_binding 的 commit 锁内调用；此处再做 exact local task owner CAS。
    fn publish_committed_result_for_owned_task(
        task_id: u64,
        attempt: &AuthAttempt,
        generation: CommittedAuthGeneration,
        mut auth_body: AuthBody,
    ) -> bool {
        auth_body.native_attempt = None;
        sanitize_auth_body_user_for_ui(&mut auth_body);
        let mut session = OIDC_SESSION.write().unwrap();
        if !session.owns_attempt(task_id, attempt) || !session.keep_querying {
            return false;
        }
        session.state_msg = LOGIN_ACCOUNT_AUTH;
        session.failed_msg.clear();
        session.code_url = None;
        session.auth_body = Some(auth_body);
        session.committed_generation = Some(generation.clone());
        session.unacked_committed = Some((attempt.clone(), generation));
        session.result_task_id = Some(task_id);
        // commit 已消费 attempt；本地结果仍保留 exact provenance 供轮询者归属。
        session.result_origin_attempt = Some(attempt.clone());
        true
    }

    fn auth_task(
        task_id: u64,
        attempt: AuthAttempt,
        op: String,
        id: String,
        uuid: String,
        _remember_me: bool,
    ) {
        let api_server = attempt.normalized_api_base.clone();
        let Some(auth_request_res) = Self::send_network_if_current_with(
            task_id,
            &attempt,
            auth_binding::is_auth_attempt_current,
            || Self::auth(&api_server, &op, &id, &uuid),
        ) else {
            return;
        };
        let code_url = match auth_request_res {
            Ok(HbbHttpResponse::<_>::Data(code_url)) => {
                log::info!("OIDC authorization request succeeded");
                code_url
            }
            Ok(HbbHttpResponse::<_>::Error(_)) => {
                Self::publish_failure_if_current(
                    task_id,
                    &attempt,
                    REQUESTING_ACCOUNT_AUTH,
                    "OIDC 授权请求失败",
                );
                return;
            }
            Ok(_) => {
                Self::publish_failure_if_current(
                    task_id,
                    &attempt,
                    REQUESTING_ACCOUNT_AUTH,
                    "OIDC 授权响应无效",
                );
                return;
            }
            Err(_) => {
                Self::publish_failure_if_current(
                    task_id,
                    &attempt,
                    REQUESTING_ACCOUNT_AUTH,
                    "OIDC 授权请求失败",
                );
                return;
            }
        };
        if !Self::auth_url_scheme_is_allowed(&code_url.url) {
            Self::publish_failure_if_current(
                task_id,
                &attempt,
                REQUESTING_ACCOUNT_AUTH,
                "OIDC 授权地址协议不安全",
            );
            return;
        }
        if !Self::publish_code_url_if_current(task_id, &attempt, code_url.clone()) {
            return;
        }

        let begin = Instant::now();
        let query_timeout = OIDC_SESSION.read().unwrap().query_timeout;
        while begin.elapsed() < query_timeout && Self::task_attempt_is_current(task_id, &attempt) {
            let Some(query_result) = Self::send_network_if_current_with(
                task_id,
                &attempt,
                auth_binding::is_auth_attempt_current,
                || Self::query(&api_server, &code_url.code, &id, &uuid),
            ) else {
                return;
            };
            if begin.elapsed() >= query_timeout {
                Self::publish_failure_if_current(
                    task_id,
                    &attempt,
                    WAITING_ACCOUNT_AUTH,
                    "OIDC 授权查询超时",
                );
                return;
            }
            match query_result {
                Ok(HbbHttpResponse::<_>::Data(mut auth_body)) => {
                    if !Self::task_attempt_is_current(task_id, &attempt) {
                        return;
                    }
                    if auth_body.r#type == "access_token" {
                        let safe_user = safe_user_from_payload(&auth_body.user);
                        let access_token = std::mem::take(&mut auth_body.access_token);
                        let commit_guard = match Self::lock_start_if_task_current(task_id, &attempt)
                        {
                            Ok(Some(guard)) => guard,
                            Ok(None) => return,
                            Err(_) => {
                                Self::publish_failure_if_current(
                                    task_id,
                                    &attempt,
                                    WAITING_ACCOUNT_AUTH,
                                    "OIDC 登录提交失败",
                                );
                                return;
                            }
                        };
                        let commit_result = auth_binding::commit_auth_attempt_with_local_owner(
                            &attempt,
                            access_token,
                            safe_user,
                            None,
                            |snapshot| {
                                let Some(session) = snapshot.session.as_ref() else {
                                    return false;
                                };
                                let generation = CommittedAuthGeneration::from_session(session);
                                auth_body.normalized_api_base =
                                    Some(session.normalized_api_base.clone());
                                auth_body.namespace = Some(session.namespace.clone());
                                auth_body.cursor_key = Some(session.cursor_key.clone());
                                auth_body.session_epoch = Some(session.session_epoch);
                                auth_body.session_nonce = Some(session.session_nonce.clone());
                                auth_body.tfa_type.clear();
                                auth_body.secret.clear();
                                auth_body.native_attempt = None;
                                Self::publish_committed_result_for_owned_task(
                                    task_id, &attempt, generation, auth_body,
                                )
                            },
                        );
                        if commit_result.is_err() {
                            drop(commit_guard);
                            Self::publish_failure_if_current(
                                task_id,
                                &attempt,
                                WAITING_ACCOUNT_AUTH,
                                "OIDC 登录提交失败",
                            );
                            return;
                        }
                    } else {
                        Self::publish_challenge_if_current(task_id, &attempt, auth_body);
                    }
                    return;
                }
                Ok(HbbHttpResponse::<_>::Error(err)) => {
                    if err.contains("No authed oidc is found") {
                        // 尚未完成认证，继续查询。
                    } else {
                        Self::publish_failure_if_current(
                            task_id,
                            &attempt,
                            WAITING_ACCOUNT_AUTH,
                            "OIDC 授权查询失败",
                        );
                        return;
                    }
                }
                Ok(_) => {
                    // 未识别的中间响应不改变当前结果。
                }
                Err(_) => {
                    log::trace!("OIDC authorization query has not completed");
                    // 暂时性网络错误由下一轮查询重试。
                }
            }
            Self::sleep(QUERY_INTERVAL_SECS);
        }

        if begin.elapsed() >= query_timeout {
            Self::publish_failure_if_current(
                task_id,
                &attempt,
                WAITING_ACCOUNT_AUTH,
                "OIDC 授权查询超时",
            );
        }

        // keep_querying 为 false 表示调用方已取消，无需再发布结果。
    }

    fn wait_stop_querying() {
        let wait_secs = 0.3;
        while OIDC_SESSION.read().unwrap().running {
            Self::sleep(wait_secs);
        }
    }

    fn clear_stopped_oidc_state(&mut self) {
        if self.running {
            return;
        }
        self.reset_visible_result();
        self.active_task_id = None;
        self.task_attempt = None;
        self.task_cancelled = false;
        self.keep_querying = false;
    }

    /// 普通 Flutter 登录开始前也必须精确终结旧 OIDC owner，并清除旧 challenge 缓存。
    pub fn begin_external_auth_attempt(api_server: String) -> ResultType<AuthAttempt> {
        let normalized_api_base = auth_binding::normalize_api_base(&api_server)?;
        auth_binding::validate_strict_target(&normalized_api_base)?;
        let _start_guard = OIDC_START_MUTEX
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("OIDC 启动锁不可用"))?;
        Self::auth_cancel_all_locked()?;
        Self::wait_stop_querying();
        let attempt = auth_binding::begin_auth_attempt(&normalized_api_base)?;
        OIDC_SESSION.write().unwrap().clear_stopped_oidc_state();
        Ok(attempt)
    }

    /// 普通/验证码登录复用 OIDC challenge attempt 时，commit 与 typed cancel 共享同一顺序锁。
    pub fn commit_external_auth_attempt(
        attempt: &AuthAttempt,
        access_token: String,
        safe_user: AuthSafeUser,
        expires_at: Option<i64>,
    ) -> ResultType<auth_binding::AuthSnapshot> {
        let _start_guard = OIDC_START_MUTEX
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("OIDC 启动锁不可用"))?;
        auth_binding::commit_auth_attempt_with_local_owner(
            attempt,
            access_token,
            safe_user,
            expires_at,
            |snapshot| {
                let Some(session) = snapshot.session.as_ref() else {
                    return false;
                };
                let generation = CommittedAuthGeneration::from_session(session);
                let mut oidc = OIDC_SESSION.write().unwrap();
                oidc.clear_cached_result_for_attempt(attempt);
                oidc.unacked_committed = Some((attempt.clone(), generation));
                true
            },
        )
    }

    pub fn account_auth(
        api_server: String,
        op: String,
        id: String,
        uuid: String,
        remember_me: bool,
    ) -> ResultType<AuthAttempt> {
        let normalized_api_base = auth_binding::normalize_api_base(&api_server)?;
        auth_binding::validate_strict_target(&normalized_api_base)?;
        let _start_guard = OIDC_START_MUTEX
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("OIDC 启动锁不可用"))?;
        Self::auth_cancel_all_locked()?;
        Self::wait_stop_querying();
        let attempt = auth_binding::begin_auth_attempt(&normalized_api_base)?;
        let task_id = match OIDC_SESSION.write().unwrap().before_task() {
            Ok(task_id) => task_id,
            Err(error) => {
                let _ = auth_binding::cancel_auth_attempt(&attempt);
                return Err(error);
            }
        };
        if !OIDC_SESSION
            .write()
            .unwrap()
            .bind_attempt(task_id, &attempt)?
        {
            // 绑定前可能被取消；此处不得遗留不可见的原生 attempt。
            let _ = auth_binding::cancel_auth_attempt(&attempt);
            OIDC_SESSION.write().unwrap().after_unbound_task(task_id);
            hbb_common::bail!("OIDC 登录任务在启动期间已取消");
        }
        let worker_attempt = attempt.clone();
        std::thread::spawn(move || {
            Self::auth_task(task_id, worker_attempt.clone(), op, id, uuid, remember_me);
            OIDC_SESSION
                .write()
                .unwrap()
                .after_task(task_id, &worker_attempt);
        });
        Ok(attempt)
    }

    fn get_result_(&self) -> AuthResult {
        AuthResult {
            state_msg: self.state_msg.to_string(),
            failed_msg: self.failed_msg.clone(),
            url: self.code_url.as_ref().map(|x| x.url.to_string()),
            auth_body: self.auth_body.clone(),
            native_attempt: self.result_origin_opaque.clone(),
        }
    }

    fn clear_committed_result_if_generation(
        &mut self,
        task_id: u64,
        origin_attempt: &AuthAttempt,
        generation: &CommittedAuthGeneration,
    ) -> bool {
        if self.result_task_id != Some(task_id)
            || self.result_origin_attempt.as_ref() != Some(origin_attempt)
            || self.committed_generation.as_ref() != Some(generation)
        {
            return false;
        }
        self.reset_visible_result();
        true
    }

    fn clear_uncommitted_result_if_attempt(
        &mut self,
        task_id: u64,
        origin_attempt: &AuthAttempt,
    ) -> bool {
        if self.result_task_id != Some(task_id)
            || self.result_origin_attempt.as_ref() != Some(origin_attempt)
            || self.committed_generation.is_some()
        {
            return false;
        }
        self.reset_visible_result();
        true
    }

    fn clear_cached_result_for_attempt(&mut self, attempt: &AuthAttempt) -> bool {
        let active_match = self.running && self.task_attempt.as_ref() == Some(attempt);
        let result_match = self.result_origin_attempt.as_ref() == Some(attempt);
        if active_match {
            self.keep_querying = false;
            self.task_cancelled = true;
        }
        if result_match {
            self.reset_visible_result();
        }
        active_match || result_match
    }

    fn clear_unacked_committed_if_exact(
        &mut self,
        attempt: &AuthAttempt,
        generation: &CommittedAuthGeneration,
    ) -> bool {
        if !self
            .unacked_committed
            .as_ref()
            .is_some_and(|(origin, current_generation)| {
                origin == attempt && current_generation == generation
            })
        {
            return false;
        }
        self.unacked_committed = None;
        true
    }

    fn acknowledge_cached_result_if_exact(
        &mut self,
        attempt: &AuthAttempt,
        generation: &CommittedAuthGeneration,
    ) -> bool {
        if !self.clear_unacked_committed_if_exact(attempt, generation) {
            return false;
        }
        if self.result_origin_attempt.as_ref() == Some(attempt) {
            self.reset_visible_result();
        }
        true
    }

    fn auth_cancel_attempt_locked(attempt: &AuthAttempt) -> ResultType<bool> {
        let unacked_generation = {
            let session = OIDC_SESSION.read().unwrap();
            session
                .unacked_committed
                .as_ref()
                .filter(|(origin, _)| origin == attempt)
                .map(|(_, generation)| generation.clone())
        };
        if let Some(generation) = unacked_generation {
            // commit 先赢但 UI 尚未 ACK 时，取消按提交代次条件回滚本地会话。
            let session_cleared =
                auth_binding::clear_auth_session_if_current(&generation.request_handle())?;
            let mut session = OIDC_SESSION.write().unwrap();
            let marker_cleared = session.clear_unacked_committed_if_exact(attempt, &generation);
            let cache_cleared = session.clear_cached_result_for_attempt(attempt);
            return Ok(session_cleared || marker_cleared || cache_cleared);
        }
        let authority_cancelled = auth_binding::cancel_auth_attempt(attempt)?;
        let local_cancelled = OIDC_SESSION
            .write()
            .unwrap()
            .clear_cached_result_for_attempt(attempt);
        Ok(authority_cancelled || local_cancelled)
    }

    /// 只取消调用方持有的 exact attempt；旧控件绝不能取消后来开始的登录。
    pub fn auth_cancel_attempt(attempt: &AuthAttempt) -> ResultType<bool> {
        let _start_guard = OIDC_START_MUTEX
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("OIDC 启动锁不可用"))?;
        Self::auth_cancel_attempt_locked(attempt)
    }

    /// UI 已接纳 exact committed DTO 后清理缓存；成功 ACK 之前 worker 不会被唤醒。
    pub fn ack_auth_attempt(attempt: &AuthAttempt) -> ResultType<bool> {
        let _start_guard = OIDC_START_MUTEX
            .lock()
            .map_err(|_| hbb_common::anyhow::anyhow!("OIDC 启动锁不可用"))?;
        let generation = {
            let session = OIDC_SESSION.read().unwrap();
            session
                .unacked_committed
                .as_ref()
                .filter(|(origin, _)| origin == attempt)
                .map(|(_, generation)| generation.clone())
        };
        let Some(generation) = generation else {
            return Ok(false);
        };
        let acknowledged = auth_binding::acknowledge_current_committed_auth_attempt_result(
            attempt,
            &generation.request_handle(),
            || {
                let mut session = OIDC_SESSION.write().unwrap();
                session.acknowledge_cached_result_if_exact(attempt, &generation)
            },
        )?;
        if acknowledged {
            crate::hbbs_http::address_book_sync::wake_worker();
        }
        Ok(acknowledged)
    }

    fn auth_cancel_all_locked() -> ResultType<()> {
        let attempts = {
            let mut session = OIDC_SESSION.write().unwrap();
            let mut attempts = Vec::new();
            if let Some(attempt) = session.task_attempt.clone() {
                attempts.push(attempt);
            }
            if let Some(attempt) = session.result_origin_attempt.clone() {
                if !attempts.contains(&attempt) {
                    attempts.push(attempt);
                }
            }
            if let Some((attempt, _)) = session.unacked_committed.clone() {
                if !attempts.contains(&attempt) {
                    attempts.push(attempt);
                }
            }
            if session.running && session.task_attempt.is_none() {
                session.keep_querying = false;
                session.task_cancelled = true;
                session.reset_visible_result();
            }
            attempts
        };
        for attempt in attempts {
            Self::auth_cancel_attempt_locked(&attempt)?;
        }
        Ok(())
    }

    pub fn get_result_for_attempt(attempt: &AuthAttempt) -> Option<AuthResult> {
        let (result_task_id, origin_attempt, committed_generation) = {
            let session = OIDC_SESSION.read().unwrap();
            (
                session.result_task_id,
                session.result_origin_attempt.clone(),
                session.committed_generation.clone(),
            )
        };
        if origin_attempt.as_ref() != Some(attempt) {
            return None;
        }
        let (Some(task_id), Some(origin_attempt)) = (result_task_id, origin_attempt.as_ref())
        else {
            return None;
        };
        let read_exact_result = || {
            let session = OIDC_SESSION.read().unwrap();
            if session.result_task_id != Some(task_id)
                || session.result_origin_attempt.as_ref() != Some(attempt)
                || session.committed_generation != committed_generation
            {
                return None;
            }
            Some(session.get_result_())
        };
        let result = match committed_generation.as_ref() {
            Some(generation) => auth_binding::with_current_committed_auth_attempt_result(
                attempt,
                &generation.request_handle(),
                read_exact_result,
            )
            .flatten(),
            None => auth_binding::with_current_auth_attempt(attempt, read_exact_result).flatten(),
        };
        if result.is_some() {
            return result;
        }

        let mut session = OIDC_SESSION.write().unwrap();
        match committed_generation.as_ref() {
            Some(generation) => {
                session.clear_committed_result_if_generation(task_id, origin_attempt, generation);
            }
            None => {
                session.clear_uncommitted_result_if_attempt(task_id, origin_attempt);
            }
        }
        None
    }
}

fn safe_user_from_payload(user: &UserPayload) -> AuthSafeUser {
    AuthSafeUser {
        id: user.id,
        name: user.name.clone(),
        display_name: option_string(&user.display_name),
        avatar: option_string(&user.avatar),
        email: option_string(&user.email),
        note: option_string(&user.note),
        status: user.status as i64,
        is_admin: user.is_admin,
        verifier: user.verifier.clone(),
    }
}

fn option_string(value: &Option<String>) -> String {
    match value {
        Some(value) => value.clone(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OIDC_SENDER_TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn attempt(attempt_id: u64, normalized_api_base: &str) -> AuthAttempt {
        AuthAttempt {
            attempt_id,
            nonce: format!("attempt-{attempt_id}"),
            normalized_api_base: normalized_api_base.to_owned(),
            logout_generation: attempt_id,
        }
    }

    fn opaque_attempt(attempt: &AuthAttempt) -> String {
        auth_binding::serialize_auth_attempt(attempt).expect("应序列化 opaque attempt")
    }

    fn user() -> UserPayload {
        UserPayload {
            id: Some(7),
            name: "alice".to_owned(),
            display_name: Some("Alice".to_owned()),
            avatar: None,
            email: None,
            note: None,
            status: UserStatus::Normal,
            info: UserInfo::default(),
            is_admin: false,
            third_auth_type: None,
            verifier: String::new(),
        }
    }

    fn committed_generation(suffix: &str, session_epoch: u64) -> CommittedAuthGeneration {
        CommittedAuthGeneration {
            normalized_api_base: format!("https://{suffix}.example.com"),
            namespace: format!("id:{suffix}"),
            cursor_key: format!("cursor-{suffix}"),
            session_epoch,
            session_nonce: format!("nonce-{suffix}"),
        }
    }

    fn committed_body(generation: &CommittedAuthGeneration) -> AuthBody {
        AuthBody {
            access_token: String::new(),
            r#type: "access_token".to_owned(),
            tfa_type: String::new(),
            secret: String::new(),
            user: user(),
            normalized_api_base: Some(generation.normalized_api_base.clone()),
            namespace: Some(generation.namespace.clone()),
            cursor_key: Some(generation.cursor_key.clone()),
            session_epoch: Some(generation.session_epoch),
            session_nonce: Some(generation.session_nonce.clone()),
            native_attempt: None,
        }
    }

    #[test]
    fn committed_oidc_result_never_serializes_token_or_secret() {
        let secret = "issue9-oidc-secret-sentinel";
        let verifier = "issue9-oidc-verifier-sentinel";
        let internal = "issue9-oidc-internal-sentinel";
        let mut output_user = user();
        output_user.verifier = verifier.to_owned();
        output_user.third_auth_type = Some(internal.to_owned());
        output_user
            .info
            .other
            .insert("private".to_owned(), internal.to_owned());
        let body = AuthBody {
            access_token: secret.to_owned(),
            r#type: "access_token".to_owned(),
            tfa_type: String::new(),
            secret: String::new(),
            user: output_user,
            normalized_api_base: Some("https://example.com".to_owned()),
            namespace: Some("id:7".to_owned()),
            cursor_key: Some("cursor-key".to_owned()),
            session_epoch: Some(11),
            session_nonce: Some("safe-nonce".to_owned()),
            native_attempt: None,
        };
        let mut body = body;
        sanitize_auth_body_user_for_ui(&mut body);

        let json = serde_json::to_string(&body).expect("应序列化安全结果");
        let value: serde_json::Value = serde_json::from_str(&json).expect("应解析安全结果");
        assert!(!json.contains(secret));
        assert!(value.get("access_token").is_none());
        assert_eq!(
            value.get("type").and_then(serde_json::Value::as_str),
            Some("access_token")
        );
        assert_eq!(
            value
                .get("normalized_api_base")
                .and_then(serde_json::Value::as_str),
            Some("https://example.com")
        );
        assert_eq!(
            value.get("namespace").and_then(serde_json::Value::as_str),
            Some("id:7")
        );
        assert_eq!(
            value.get("cursor_key").and_then(serde_json::Value::as_str),
            Some("cursor-key")
        );
        assert!(json.contains("session_epoch"));
        assert!(!json.contains(verifier));
        assert!(!json.contains(internal));
        assert!(value["user"].get("verifier").is_none());
        assert!(!format!("{body:?}").contains(secret));
        assert!(!format!("{body:?}").contains(verifier));
    }

    #[test]
    fn oidc_result_keeps_origin_for_committed_and_challenge_results() {
        let origin = attempt(7, "https://example.com");
        let opaque_origin = opaque_attempt(&origin);
        let generation = committed_generation("committed", 11);
        let committed = AuthResult {
            state_msg: LOGIN_ACCOUNT_AUTH.to_owned(),
            failed_msg: String::new(),
            url: None,
            auth_body: Some(committed_body(&generation)),
            native_attempt: Some(opaque_origin.clone()),
        };
        let committed_json = serde_json::to_value(committed).expect("应序列化已提交 OIDC 结果");
        assert_eq!(
            committed_json["native_attempt"].as_str(),
            Some(opaque_origin.as_str())
        );
        assert!(committed_json["auth_body"].get("native_attempt").is_none());
        assert_eq!(
            committed_json["auth_body"]["session_epoch"].as_u64(),
            Some(generation.session_epoch)
        );

        let challenge = AuthResult {
            state_msg: LOGIN_ACCOUNT_AUTH.to_owned(),
            failed_msg: String::new(),
            url: None,
            auth_body: Some(AuthBody {
                access_token: String::new(),
                r#type: "tfa".to_owned(),
                tfa_type: "totp".to_owned(),
                secret: "challenge-secret".to_owned(),
                user: user(),
                normalized_api_base: None,
                namespace: None,
                cursor_key: None,
                session_epoch: None,
                session_nonce: None,
                native_attempt: Some(opaque_origin.clone()),
            }),
            native_attempt: Some(opaque_origin.clone()),
        };
        let challenge_json = serde_json::to_value(challenge).expect("应序列化 OIDC 挑战结果");
        assert_eq!(
            challenge_json["native_attempt"].as_str(),
            Some(opaque_origin.as_str())
        );
        assert_eq!(
            challenge_json["auth_body"]["native_attempt"].as_str(),
            Some(opaque_origin.as_str())
        );
    }

    #[test]
    fn safe_user_conversion_preserves_immutable_id() {
        let safe = safe_user_from_payload(&user());
        assert_eq!(safe.id, Some(7));
        assert_eq!(safe.name, "alice");
        assert_eq!(safe.display_name, "Alice");
    }

    #[test]
    fn stale_oidc_generation_only_clears_its_own_cached_result() {
        let origin_a = attempt(1, "https://a.example.com");
        let origin_b = attempt(2, "https://b.example.com");
        let generation_a = committed_generation("a", 11);
        let generation_b = committed_generation("b", 12);
        let mut session = OidcSession::new();
        session.state_msg = LOGIN_ACCOUNT_AUTH;
        session.result_task_id = Some(2);
        session.result_origin_attempt = Some(origin_b.clone());
        session.auth_body = Some(committed_body(&generation_b));
        session.committed_generation = Some(generation_b.clone());

        assert!(!session.clear_committed_result_if_generation(1, &origin_a, &generation_a));
        assert!(!session.clear_committed_result_if_generation(1, &origin_b, &generation_b));
        assert_eq!(session.committed_generation, Some(generation_b.clone()));
        assert!(session.auth_body.is_some());

        assert!(session.clear_committed_result_if_generation(2, &origin_b, &generation_b));
        assert!(session.committed_generation.is_none());
        assert!(session.auth_body.is_none());
        assert!(session.result_origin_attempt.is_none());
        assert_eq!(session.state_msg, REQUESTING_ACCOUNT_AUTH);
    }

    #[test]
    fn stale_oidc_challenge_only_clears_its_own_attempt() {
        let attempt_a = attempt(1, "https://a.example.com");
        let attempt_b = attempt(2, "https://b.example.com");
        let mut session = OidcSession::new();
        session.state_msg = LOGIN_ACCOUNT_AUTH;
        session.result_task_id = Some(2);
        session.result_origin_attempt = Some(attempt_b.clone());
        session.auth_body = Some(AuthBody {
            access_token: String::new(),
            r#type: "tfa".to_owned(),
            tfa_type: "totp".to_owned(),
            secret: "challenge-secret".to_owned(),
            user: user(),
            normalized_api_base: None,
            namespace: None,
            cursor_key: None,
            session_epoch: None,
            session_nonce: None,
            native_attempt: Some(opaque_attempt(&attempt_b)),
        });

        assert!(!session.clear_uncommitted_result_if_attempt(1, &attempt_a));
        assert!(!session.clear_uncommitted_result_if_attempt(1, &attempt_b));
        assert_eq!(session.result_origin_attempt, Some(attempt_b.clone()));
        assert!(session.auth_body.is_some());

        assert!(session.clear_uncommitted_result_if_attempt(2, &attempt_b));
        assert!(session.result_origin_attempt.is_none());
        assert!(session.auth_body.is_none());
        assert_eq!(session.state_msg, REQUESTING_ACCOUNT_AUTH);
    }

    #[test]
    fn stale_worker_cannot_finish_or_clear_newer_task() {
        let attempt_a = attempt(1, "https://a.example.com");
        let attempt_b = attempt(2, "https://b.example.com");
        let mut session = OidcSession::new();
        let task_a = session.before_task().expect("应创建任务 A");
        assert!(session
            .bind_attempt(task_a, &attempt_a)
            .expect("应绑定任务 A"));
        assert!(session.after_task(task_a, &attempt_a));

        let task_b = session.before_task().expect("应创建任务 B");
        assert!(task_b > task_a);
        assert!(session
            .bind_attempt(task_b, &attempt_b)
            .expect("应绑定任务 B"));
        assert!(!session.after_task(task_a, &attempt_a));
        assert!(session.owns_attempt(task_b, &attempt_b));
        assert!(!session.clear_uncommitted_result_if_attempt(task_a, &attempt_a));
        assert_eq!(session.result_origin_attempt, Some(attempt_b.clone()));
    }

    #[test]
    fn exact_cache_clear_only_removes_matching_origin() {
        let attempt_a = attempt(1, "https://a.example.com");
        let attempt_b = attempt(2, "https://b.example.com");
        let generation_b = committed_generation("b", 12);
        let mut session = OidcSession::new();
        let task_b = session.before_task().expect("应创建任务 B");
        assert!(session
            .bind_attempt(task_b, &attempt_b)
            .expect("应绑定任务 B"));
        session.state_msg = LOGIN_ACCOUNT_AUTH;
        session.auth_body = Some(committed_body(&generation_b));
        session.committed_generation = Some(generation_b);

        assert!(!session.clear_cached_result_for_attempt(&attempt_a));
        assert!(session.running);
        assert!(session.auth_body.is_some());

        assert!(session.clear_cached_result_for_attempt(&attempt_b));
        assert!(session.task_cancelled);
        assert!(!session.keep_querying);
        assert!(session.auth_body.is_none());
        assert!(session.committed_generation.is_none());
        assert!(session.result_origin_attempt.is_none());
        // task_attempt 只用于让旧 worker 精确收尾，不代表撤销已提交的认证权威会话。
        assert_eq!(session.task_attempt, Some(attempt_b));
    }

    #[test]
    fn committed_ack_clears_only_exact_marker_and_dto_cache() {
        let attempt_a = attempt(1, "https://a.example.com");
        let attempt_b = attempt(2, "https://b.example.com");
        let generation_a = committed_generation("a", 11);
        let generation_b = committed_generation("b", 12);
        let mut session = OidcSession::new();
        session.result_task_id = Some(2);
        session.result_origin_attempt = Some(attempt_b.clone());
        session.result_origin_opaque = Some(opaque_attempt(&attempt_b));
        session.auth_body = Some(committed_body(&generation_b));
        session.committed_generation = Some(generation_b.clone());
        session.unacked_committed = Some((attempt_b.clone(), generation_b.clone()));

        assert!(!session.acknowledge_cached_result_if_exact(&attempt_a, &generation_a));
        assert_eq!(
            session.unacked_committed,
            Some((attempt_b.clone(), generation_b.clone()))
        );
        assert!(session.auth_body.is_some());

        assert!(session.acknowledge_cached_result_if_exact(&attempt_b, &generation_b));
        assert!(session.unacked_committed.is_none());
        assert!(session.auth_body.is_none());
        assert!(session.committed_generation.is_none());
        assert!(session.result_origin_attempt.is_none());
        assert!(session.result_origin_opaque.is_none());
    }

    #[test]
    fn every_oidc_sender_requires_exact_local_owner_and_current_attempt() {
        let _test_guard = OIDC_SENDER_TEST_MUTEX.lock().unwrap();
        let attempt_a = attempt(1, "https://a.example.com");
        let attempt_b = attempt(2, "https://b.example.com");
        *OIDC_SESSION.write().unwrap() = OidcSession::new();
        let task_a = OIDC_SESSION
            .write()
            .unwrap()
            .before_task()
            .expect("应创建任务 A");
        assert!(OIDC_SESSION
            .write()
            .unwrap()
            .bind_attempt(task_a, &attempt_a)
            .expect("应绑定任务 A"));

        let sends = AtomicUsize::new(0);
        let stale_initial_result = OidcSession::send_network_if_current_with(
            task_a,
            &attempt_a,
            |candidate| candidate == &attempt_b,
            || sends.fetch_add(1, Ordering::SeqCst),
        );
        assert!(stale_initial_result.is_none());
        let stale_query_result = OidcSession::send_network_if_current_with(
            task_a,
            &attempt_a,
            |candidate| candidate == &attempt_b,
            || sends.fetch_add(1, Ordering::SeqCst),
        );
        assert!(stale_query_result.is_none());
        assert_eq!(sends.load(Ordering::SeqCst), 0);

        assert!(OIDC_SESSION
            .write()
            .unwrap()
            .clear_cached_result_for_attempt(&attempt_a));
        let cancelled_result = OidcSession::send_network_if_current_with(
            task_a,
            &attempt_a,
            |_| true,
            || sends.fetch_add(1, Ordering::SeqCst),
        );
        assert!(cancelled_result.is_none());
        assert_eq!(sends.load(Ordering::SeqCst), 0);

        *OIDC_SESSION.write().unwrap() = OidcSession::new();
        let task_b = OIDC_SESSION
            .write()
            .unwrap()
            .before_task()
            .expect("应创建任务 B");
        assert!(OIDC_SESSION
            .write()
            .unwrap()
            .bind_attempt(task_b, &attempt_b)
            .expect("应绑定任务 B"));
        let current_result = OidcSession::send_network_if_current_with(
            task_b,
            &attempt_b,
            |candidate| candidate == &attempt_b,
            || sends.fetch_add(1, Ordering::SeqCst),
        );
        assert_eq!(current_result, Some(0));
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        *OIDC_SESSION.write().unwrap() = OidcSession::new();
    }

    #[test]
    fn beginning_an_external_login_clears_stopped_oidc_challenge_cache() {
        let attempt = attempt(1, "https://example.com");
        let mut session = OidcSession::new();
        let task = session.before_task().expect("应创建 OIDC 任务");
        assert!(session
            .bind_attempt(task, &attempt)
            .expect("应绑定 OIDC attempt"));
        session.auth_body = Some(AuthBody {
            access_token: String::new(),
            r#type: "tfa".to_owned(),
            tfa_type: "totp".to_owned(),
            secret: "challenge-secret".to_owned(),
            user: user(),
            normalized_api_base: None,
            namespace: None,
            cursor_key: None,
            session_epoch: None,
            session_nonce: None,
            native_attempt: Some(opaque_attempt(&attempt)),
        });
        session.state_msg = LOGIN_ACCOUNT_AUTH;
        assert!(session.after_task(task, &attempt));

        session.clear_stopped_oidc_state();
        assert!(session.auth_body.is_none());
        assert!(session.result_origin_attempt.is_none());
        assert!(session.result_origin_opaque.is_none());
        assert!(session.task_attempt.is_none());
        assert!(session.active_task_id.is_none());
    }

    #[test]
    fn oidc_browser_url_only_accepts_https_or_loopback_http() {
        assert!(OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("https://example.com/login").unwrap()
        ));
        assert!(OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("http://127.0.0.1:8000/login").unwrap()
        ));
        assert!(OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("http://[::1]:8000/login").unwrap()
        ));
        assert!(OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("http://localhost:8000/login").unwrap()
        ));
        assert!(!OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("http://example.com/login").unwrap()
        ));
        assert!(!OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("javascript:alert(1)").unwrap()
        ));
        assert!(!OidcSession::auth_url_scheme_is_allowed(
            &Url::parse("rustdesk://login").unwrap()
        ));
    }
}
