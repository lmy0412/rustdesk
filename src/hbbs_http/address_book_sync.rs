use hbb_common::{anyhow::anyhow, bail, ResultType};
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "flutter", test))]
use sha2::{Digest, Sha256};
#[cfg(any(feature = "flutter", test))]
use std::time::Duration;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
#[cfg(any(feature = "flutter", test))]
const POLL_BASE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(any(feature = "flutter", test))]
const POLL_JITTER_BOUND: Duration = Duration::from_secs(10);

#[cfg(any(feature = "flutter", test))]
fn stable_poll_jitter(device_id: &str, instance_id: &str) -> Duration {
    let mut hasher = Sha256::new();
    hasher.update(b"rustdesk-address-book-poll-jitter-v1\0");
    hasher.update(device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(instance_id.as_bytes());
    let digest = hasher.finalize();
    let mut sample = [0u8; 8];
    sample.copy_from_slice(&digest[..8]);
    let bound_millis = POLL_JITTER_BOUND.as_millis() as u64;
    Duration::from_millis(u64::from_le_bytes(sample) % (bound_millis + 1))
}

#[cfg(any(feature = "flutter", test))]
fn poll_interval_for_identity(device_id: &str, instance_id: &str) -> Duration {
    POLL_BASE_INTERVAL + stable_poll_jitter(device_id, instance_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookItem {
    pub device_id: String,
    pub instance_id: String,
    pub alias: String,
    pub hostname: String,
    pub os: String,
    pub source: String,
    pub permission: String,
    pub share_id: Option<i64>,
    pub shared_by_user_id: Option<i64>,
    pub shared_by_username: Option<String>,
}

impl AddressBookItem {
    pub fn validate(&self) -> ResultType<()> {
        validate_device_id(&self.device_id)?;
        validate_instance_id(&self.instance_id)?;
        validate_safe_device_text_fields(&self.alias, &self.hostname, &self.os)?;
        match self.source.as_str() {
            "owned" => {
                if self.permission != "full_control"
                    || self.share_id.is_some()
                    || self.shared_by_user_id.is_some()
                    || self.shared_by_username.is_some()
                {
                    bail!("自有设备地址簿字段组合无效");
                }
            }
            "shared" => {
                if !matches!(self.permission.as_str(), "view_only" | "full_control")
                    || self.share_id.is_none()
                    || self.shared_by_user_id.is_none()
                    || self.shared_by_username.is_none()
                {
                    bail!("共享设备地址簿字段组合无效");
                }
                let share_id = self
                    .share_id
                    .ok_or_else(|| anyhow!("共享设备缺少 share_id"))?;
                let shared_by_user_id = self
                    .shared_by_user_id
                    .ok_or_else(|| anyhow!("共享设备缺少 shared_by_user_id"))?;
                let shared_by_username = self
                    .shared_by_username
                    .as_deref()
                    .ok_or_else(|| anyhow!("共享设备缺少 shared_by_username"))?;
                validate_safe_id(share_id, "share_id", 1)?;
                validate_safe_id(shared_by_user_id, "shared_by_user_id", 1)?;
                validate_username(shared_by_username)?;
            }
            _ => bail!("地址簿来源无效"),
        }
        Ok(())
    }

    pub fn identity(&self) -> (&str, &str) {
        (&self.device_id, &self.instance_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookChange {
    pub version: i64,
    pub operation: String,
    pub device_id: String,
    pub instance_id: String,
    pub share_id: Option<i64>,
    pub item: Option<AddressBookItem>,
}

impl AddressBookChange {
    fn validate(&self) -> ResultType<()> {
        validate_safe_id(self.version, "version", 1)?;
        validate_device_id(&self.device_id)?;
        validate_instance_id(&self.instance_id)?;
        if let Some(share_id) = self.share_id {
            validate_safe_id(share_id, "share_id", 1)?;
        }
        match self.operation.as_str() {
            "upsert" => {
                let item = self
                    .item
                    .as_ref()
                    .ok_or_else(|| anyhow!("upsert缺少地址簿条目"))?;
                item.validate()?;
                if item.device_id != self.device_id
                    || item.instance_id != self.instance_id
                    || item.share_id != self.share_id
                {
                    bail!("地址簿变更identity不一致");
                }
            }
            "delete" if self.item.is_none() => {}
            _ => bail!("地址簿变更operation无效"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookDelta {
    pub mode: String,
    pub ab_ver: i64,
    pub next_ab_ver: i64,
    pub changes: Vec<AddressBookChange>,
    pub page_size: i64,
    pub has_more: bool,
    pub reset_required: bool,
}

impl AddressBookDelta {
    pub fn parse(body: &str, requested_cursor: i64) -> ResultType<Self> {
        validate_safe_id(requested_cursor, "requested_cursor", 0)?;
        let value: Self = serde_json::from_str(body)?;
        value.validate(requested_cursor)?;
        Ok(value)
    }

    pub fn validate(&self, requested_cursor: i64) -> ResultType<()> {
        if self.mode != "delta" {
            bail!("地址簿响应mode无效");
        }
        validate_safe_id(self.ab_ver, "ab_ver", 0)?;
        validate_safe_id(self.next_ab_ver, "next_ab_ver", 0)?;
        if !self.reset_required && self.ab_ver < requested_cursor {
            bail!("地址簿响应未授权cursor降版");
        }
        if !(1..=200).contains(&self.page_size) {
            bail!("地址簿响应page_size无效");
        }
        let mut expected = if self.reset_required {
            1
        } else {
            requested_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("地址簿cursor溢出"))?
        };
        for change in &self.changes {
            change.validate()?;
            if change.version != expected {
                bail!("地址簿变更版本不连续");
            }
            expected = expected
                .checked_add(1)
                .ok_or_else(|| anyhow!("地址簿变更版本溢出"))?;
        }
        if let Some(last) = self.changes.last() {
            if last.version != self.next_ab_ver {
                bail!("地址簿next_ab_ver与末条变更不一致");
            }
        } else if self.next_ab_ver != self.ab_ver {
            bail!("空地址簿delta的cursor无效");
        }
        if self.next_ab_ver > self.ab_ver || self.has_more != (self.next_ab_ver < self.ab_ver) {
            bail!("地址簿delta分页状态无效");
        }
        Ok(())
    }

    pub fn needs_refresh(&self, requested_cursor: i64) -> bool {
        self.reset_required || self.ab_ver != requested_cursor || !self.changes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SysinfoAddressBookResponse {
    pub status: String,
    pub address_book: AddressBookDelta,
}

impl SysinfoAddressBookResponse {
    pub fn parse(body: &str, requested_cursor: i64) -> ResultType<Self> {
        let value: Self = serde_json::from_str(body)?;
        if value.status != "SYSINFO_UPDATED" {
            bail!("sysinfo地址簿状态无效");
        }
        value.address_book.validate(requested_cursor)?;
        Ok(value)
    }
}

fn validate_safe_id(value: i64, field: &str, minimum: i64) -> ResultType<()> {
    if value < minimum || value > MAX_SAFE_INTEGER {
        bail!("{field}超出安全整数范围");
    }
    Ok(())
}

fn validate_device_id(value: &str) -> ResultType<()> {
    if value.is_empty()
        || value.chars().count() > 100
        || value.chars().any(|ch| ch == '\0' || ch.is_control())
    {
        bail!("device_id无效");
    }
    Ok(())
}

fn validate_safe_device_text_fields(alias: &str, hostname: &str, os: &str) -> ResultType<()> {
    if alias.chars().count() > 200 || alias.chars().any(char::is_control) {
        bail!("alias无效");
    }
    if hostname.len() > 200 || hostname.chars().any(char::is_control) {
        bail!("hostname无效");
    }
    if os.len() > 100 || os.chars().any(char::is_control) {
        bail!("os无效");
    }
    Ok(())
}

fn validate_username(value: &str) -> ResultType<()> {
    if value.is_empty() || value.chars().count() > 100 || value.chars().any(char::is_control) {
        bail!("shared_by_username无效");
    }
    Ok(())
}

fn validate_instance_id(value: &str) -> ResultType<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("instance_id无效");
    }
    Ok(())
}

#[cfg(feature = "flutter")]
mod worker {
    use super::{
        poll_interval_for_identity, AddressBookDelta, SysinfoAddressBookResponse, MAX_SAFE_INTEGER,
    };
    use crate::{
        common::{strict_http_request, StrictHttpMethod, StrictHttpRequest, StrictHttpResponse},
        hbbs_http::auth_binding::{
            auth_snapshot, authorize_address_book_reset,
            clear_address_book_reset_authorization_if_current, clear_auth_session_if_current,
            credentialed_request_handle, is_request_current, mark_pro_if_current,
            CredentialedRequestHandle,
        },
        hbbs_http::auth_state_store::AddressBookCapability,
    };
    use hbb_common::{config::Config, log, tokio};
    use serde_json::json;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Condvar, Mutex, OnceLock,
        },
        time::Duration,
    };
    use url::Url;

    const WORKER_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
    const CANCELLATION_CHECK_INTERVAL: Duration = Duration::from_millis(25);
    static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
    static WORKER_WAKE_GENERATION: AtomicU64 = AtomicU64::new(0);
    static WORKER_SIGNAL: OnceLock<(Mutex<bool>, Condvar)> = OnceLock::new();
    static PENDING_AUTH_CLEARED_EVENT: OnceLock<Mutex<Option<String>>> = OnceLock::new();

    fn signal() -> &'static (Mutex<bool>, Condvar) {
        WORKER_SIGNAL.get_or_init(|| (Mutex::new(false), Condvar::new()))
    }

    pub fn ensure_started() {
        if WORKER_STARTED.swap(true, Ordering::AcqRel) {
            wake();
            return;
        }
        std::thread::spawn(worker_loop);
    }

    pub fn wake() {
        WORKER_WAKE_GENERATION.fetch_add(1, Ordering::AcqRel);
        let (lock, condvar) = signal();
        if let Ok(mut pending) = lock.lock() {
            *pending = true;
            condvar.notify_one();
        }
    }

    fn worker_loop() {
        loop {
            if let Err(error) = poll_once() {
                log::debug!("地址簿通知探测失败: {}", error);
            }
            let (lock, condvar) = signal();
            let Ok(pending) = lock.lock() else {
                return;
            };
            let poll_interval = current_poll_interval();
            let Ok((mut pending, _)) =
                condvar.wait_timeout_while(pending, poll_interval, |pending| !*pending)
            else {
                return;
            };
            *pending = false;
        }
    }

    fn poll_once() -> hbb_common::ResultType<()> {
        flush_pending_auth_cleared_event();
        if !crate::flutter::is_address_book_consumer_ready() {
            return Ok(());
        }
        let snapshot = auth_snapshot()?;
        let Some(session) = snapshot.session else {
            return Ok(());
        };
        if session.cursor > MAX_SAFE_INTEGER as u64 {
            hbb_common::bail!("地址簿cursor超出安全整数范围");
        }
        if session.capability == AddressBookCapability::Unknown {
            if session.force_full_pending {
                let target = endpoint(&session.normalized_api_base, "api/ab")?;
                let handle = credentialed_request_handle(&target)?;
                push_refresh_event(
                    &handle,
                    session.cursor as i64,
                    None,
                    false,
                    "capability_probe",
                );
            }
            return Ok(());
        }
        if matches!(
            session.capability,
            AddressBookCapability::Legacy | AddressBookCapability::CommercialMulti
        ) {
            return Ok(());
        }
        let requested_cursor = session.cursor as i64;
        if let Some(identity) = valid_device_identity() {
            let sysinfo_url = endpoint(&session.normalized_api_base, "api/sysinfo")?;
            let handle = credentialed_request_handle(&sysinfo_url)?;
            let body = json!({
                "id": identity.0,
                "uuid": identity.1,
                "ab_ver": requested_cursor,
                "address_book_json": true,
            })
            .to_string();
            let Some(response) = strict_http_request_cancellable(
                &handle,
                StrictHttpRequest::new(StrictHttpMethod::Post, sysinfo_url)
                    .json_body(body)
                    .timeout(WORKER_HTTP_TIMEOUT),
            )?
            else {
                return Ok(());
            };
            if !is_request_current(&handle) {
                return Ok(());
            }
            match response.status {
                204 => {
                    mark_pro_if_current(&handle)?;
                    if session.force_full_pending {
                        push_refresh_event(
                            &handle,
                            requested_cursor,
                            Some(requested_cursor),
                            false,
                            "force_full_pending",
                        );
                    } else {
                        clear_address_book_reset_authorization_if_current(&handle)?;
                    }
                    return Ok(());
                }
                200 if response.body.trim() == "ID_NOT_FOUND" => {}
                200 if response.body.trim() == "SYSINFO_UPDATED" => {
                    mark_pro_if_current(&handle)?;
                    push_refresh_event(&handle, requested_cursor, None, false, "sysinfo_sentinel");
                    return Ok(());
                }
                200 => {
                    if !is_json_content_type(response.content_type.as_deref()) {
                        hbb_common::bail!("sysinfo地址簿响应Content-Type无效");
                    }
                    let parsed =
                        SysinfoAddressBookResponse::parse(&response.body, requested_cursor)?;
                    mark_pro_if_current(&handle)?;
                    if session.force_full_pending
                        || parsed.address_book.needs_refresh(requested_cursor)
                    {
                        push_refresh_event(
                            &handle,
                            requested_cursor,
                            Some(parsed.address_book.ab_ver),
                            parsed.address_book.reset_required,
                            "sysinfo_json",
                        );
                    } else if !parsed.address_book.reset_required {
                        clear_address_book_reset_authorization_if_current(&handle)?;
                    }
                    return Ok(());
                }
                401 => {
                    clear_auth_on_unauthorized(&handle, "sysinfo")?;
                    return Ok(());
                }
                status => hbb_common::bail!("sysinfo返回HTTP {}", status),
            }
        }
        poll_address_book(
            &session.normalized_api_base,
            requested_cursor,
            session.force_full_pending,
        )
    }

    fn poll_address_book(
        normalized_base: &str,
        requested_cursor: i64,
        force_full_pending: bool,
    ) -> hbb_common::ResultType<()> {
        let mut url = Url::parse(&endpoint(normalized_base, "api/ab")?)?;
        url.query_pairs_mut()
            .append_pair("ab_ver", &requested_cursor.to_string())
            .append_pair("page_size", "1");
        let target = url.to_string();
        let handle = credentialed_request_handle(&target)?;
        let Some(response) = strict_http_request_cancellable(
            &handle,
            StrictHttpRequest::new(StrictHttpMethod::Get, target).timeout(WORKER_HTTP_TIMEOUT),
        )?
        else {
            return Ok(());
        };
        if !is_request_current(&handle) {
            return Ok(());
        }
        match response.status {
            200 => {
                if !is_json_content_type(response.content_type.as_deref()) {
                    hbb_common::bail!("地址簿探测响应Content-Type无效");
                }
                let parsed = AddressBookDelta::parse(&response.body, requested_cursor)?;
                mark_pro_if_current(&handle)?;
                if force_full_pending || parsed.needs_refresh(requested_cursor) {
                    push_refresh_event(
                        &handle,
                        requested_cursor,
                        Some(parsed.ab_ver),
                        parsed.reset_required,
                        "address_book_probe",
                    );
                } else if !parsed.reset_required {
                    clear_address_book_reset_authorization_if_current(&handle)?;
                }
                Ok(())
            }
            401 => {
                clear_auth_on_unauthorized(&handle, "address_book_probe")?;
                Ok(())
            }
            status => hbb_common::bail!("地址簿探测返回HTTP {}", status),
        }
    }

    fn endpoint(base: &str, suffix: &str) -> hbb_common::ResultType<String> {
        let mut url = Url::parse(base)?;
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}/{suffix}"));
        url.set_query(None);
        url.set_fragment(None);
        Ok(url.to_string())
    }

    fn is_json_content_type(content_type: Option<&str>) -> bool {
        content_type
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    }

    fn valid_device_identity() -> Option<(String, String)> {
        let id = Config::get_id();
        if id.is_empty()
            || id.chars().count() > 100
            || id.chars().any(|character| character.is_control())
        {
            return None;
        }
        let uuid = crate::encode64(hbb_common::get_uuid());
        if uuid.is_empty() {
            return None;
        }
        Some((id, uuid))
    }

    fn current_poll_interval() -> Duration {
        let id = Config::get_id();
        let uuid = crate::encode64(hbb_common::get_uuid());
        poll_interval_for_identity(&id, &uuid)
    }

    fn strict_http_request_cancellable(
        handle: &CredentialedRequestHandle,
        request: StrictHttpRequest,
    ) -> hbb_common::ResultType<Option<StrictHttpResponse>> {
        let wake_generation = WORKER_WAKE_GENERATION.load(Ordering::Acquire);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| hbb_common::anyhow::anyhow!("无法创建地址簿 worker runtime"))?;
        let result = runtime.block_on(async {
            tokio::select! {
                response = strict_http_request(handle, request) => response.map(Some),
                _ = wait_until_cancelled(handle, wake_generation) => Ok(None),
            }
        });
        // 取消后不等待 DNS/TLS 的后台阻塞任务，保证 logout/换代 wake 能及时返回。
        runtime.shutdown_timeout(Duration::from_millis(100));
        result
    }

    async fn wait_until_cancelled(handle: &CredentialedRequestHandle, wake_generation: u64) {
        loop {
            if WORKER_WAKE_GENERATION.load(Ordering::Acquire) != wake_generation
                || !is_request_current(handle)
            {
                return;
            }
            tokio::time::sleep(CANCELLATION_CHECK_INTERVAL).await;
        }
    }

    fn clear_auth_on_unauthorized(
        handle: &CredentialedRequestHandle,
        source: &str,
    ) -> hbb_common::ResultType<()> {
        if !clear_auth_session_if_current(handle)? {
            return Ok(());
        }
        let snapshot = auth_snapshot()?;
        let event = auth_cleared_event(
            handle,
            snapshot.auth_epoch,
            snapshot.logout_generation,
            source,
        );
        if let Ok(mut pending) = PENDING_AUTH_CLEARED_EVENT
            .get_or_init(|| Mutex::new(None))
            .lock()
        {
            *pending = Some(event.to_string());
        }
        flush_pending_auth_cleared_event();
        wake();
        Ok(())
    }

    fn flush_pending_auth_cleared_event() {
        if !crate::flutter::is_address_book_consumer_ready() {
            return;
        }
        let pending = PENDING_AUTH_CLEARED_EVENT.get_or_init(|| Mutex::new(None));
        let Some(event) = pending.lock().ok().and_then(|pending| pending.clone()) else {
            return;
        };
        if matches!(
            crate::flutter::push_global_event(crate::flutter::APP_TYPE_MAIN, event.clone()),
            Some(true)
        ) {
            if let Ok(mut pending) = pending.lock() {
                if pending.as_deref() == Some(event.as_str()) {
                    *pending = None;
                }
            }
        }
    }

    fn auth_cleared_event(
        handle: &CredentialedRequestHandle,
        auth_epoch: u64,
        logout_generation: u64,
        source: &str,
    ) -> serde_json::Value {
        json!({
            "name": "native_auth_cleared",
            "reason": "unauthorized",
            "cleared_session_epoch": handle.session_epoch,
            "cleared_session_nonce": handle.session_nonce,
            "auth_epoch": auth_epoch,
            "logout_generation": logout_generation,
            "source": source,
        })
    }

    fn push_refresh_event(
        handle: &crate::hbbs_http::auth_binding::CredentialedRequestHandle,
        requested_cursor: i64,
        target_cursor: Option<i64>,
        reset_required: bool,
        source: &str,
    ) {
        if !is_request_current(handle) || !crate::flutter::is_address_book_consumer_ready() {
            return;
        }
        let mut reset_authorized = false;
        if reset_required {
            let Some(target_cursor) = target_cursor else {
                return;
            };
            let Ok(expected_cursor) = u64::try_from(requested_cursor) else {
                return;
            };
            let Ok(target_cursor) = u64::try_from(target_cursor) else {
                return;
            };
            if !authorize_address_book_reset(handle, expected_cursor, target_cursor)
                .unwrap_or(false)
            {
                return;
            }
            reset_authorized = true;
        } else {
            let _ = clear_address_book_reset_authorization_if_current(handle);
        }
        let event = json!({
            "name": "address_book_updated",
            "requested_ab_ver": requested_cursor,
            "target_ab_ver": target_cursor,
            "reset_required": reset_required,
            "session_epoch": handle.session_epoch,
            "session_nonce": handle.session_nonce,
            "source": source,
        });
        let delivered = matches!(
            crate::flutter::push_global_event(crate::flutter::APP_TYPE_MAIN, event.to_string()),
            Some(true)
        );
        if reset_authorized && !delivered {
            let _ = clear_address_book_reset_authorization_if_current(handle);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn wake_interrupts_worker_wait_without_waiting_for_poll_interval() {
            let captured = WORKER_WAKE_GENERATION.load(Ordering::Acquire);
            let thread = std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                wake();
            });
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("应创建测试 runtime");
            let started = Instant::now();
            let interrupted = runtime.block_on(async {
                tokio::select! {
                    _ = std::future::pending::<()>() => false,
                    _ = async {
                        while WORKER_WAKE_GENERATION.load(Ordering::Acquire) == captured {
                            tokio::time::sleep(CANCELLATION_CHECK_INTERVAL).await;
                        }
                    } => true,
                }
            });
            thread.join().expect("wake 线程应结束");
            assert!(interrupted, "wake 应取消仍阻塞的旧请求分支");
            assert!(started.elapsed() < Duration::from_millis(250));
        }

        #[test]
        fn unauthorized_event_carries_cleared_generation() {
            let handle = CredentialedRequestHandle {
                request_context_id: "request".to_owned(),
                normalized_api_base: "https://example.com".to_owned(),
                namespace: "id:1".to_owned(),
                session_epoch: 7,
                session_nonce: "nonce-a".to_owned(),
                cursor_key: "cursor".to_owned(),
            };
            let event = auth_cleared_event(&handle, 8, 3, "sysinfo");
            assert_eq!(event["name"], "native_auth_cleared");
            assert_eq!(event["reason"], "unauthorized");
            assert_eq!(event["cleared_session_epoch"], 7);
            assert_eq!(event["cleared_session_nonce"], "nonce-a");
            assert_eq!(event["auth_epoch"], 8);
            assert_eq!(event["logout_generation"], 3);
            assert_eq!(event["source"], "sysinfo");
        }
    }
}

#[cfg(feature = "flutter")]
pub use worker::{ensure_started as ensure_worker_started, wake as wake_worker};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item() -> serde_json::Value {
        json!({
            "device_id": "100001",
            "instance_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "alias": "财务前台",
            "hostname": "DESKTOP-A01",
            "os": "Windows",
            "source": "owned",
            "permission": "full_control",
            "share_id": null,
            "shared_by_user_id": null,
            "shared_by_username": null
        })
    }

    #[test]
    fn delta_contract_accepts_contiguous_changes() {
        let body = json!({
            "mode": "delta",
            "ab_ver": 2,
            "next_ab_ver": 2,
            "changes": [{
                "version": 2,
                "operation": "upsert",
                "device_id": "100001",
                "instance_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "share_id": null,
                "item": item()
            }],
            "page_size": 50,
            "has_more": false,
            "reset_required": false
        });
        let parsed = AddressBookDelta::parse(&body.to_string(), 1).unwrap();
        assert!(parsed.needs_refresh(1));
    }

    #[test]
    fn delta_contract_rejects_identity_mismatch_and_gaps() {
        let mut changed_item = item();
        changed_item["device_id"] = json!("other");
        let body = json!({
            "mode": "delta",
            "ab_ver": 3,
            "next_ab_ver": 3,
            "changes": [{
                "version": 3,
                "operation": "upsert",
                "device_id": "100001",
                "instance_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "share_id": null,
                "item": changed_item
            }],
            "page_size": 50,
            "has_more": false,
            "reset_required": false
        });
        assert!(AddressBookDelta::parse(&body.to_string(), 1).is_err());
    }

    #[test]
    fn address_book_item_text_boundaries_match_server_contract() {
        fn validate(mut value: serde_json::Value, field: &str, text: String) -> bool {
            value[field] = json!(text);
            serde_json::from_value::<AddressBookItem>(value)
                .is_ok_and(|item| item.validate().is_ok())
        }

        assert!(validate(item(), "device_id", "😀".repeat(100)));
        assert!(!validate(item(), "device_id", "😀".repeat(101)));
        assert!(!validate(item(), "device_id", "device\n".to_owned()));

        assert!(validate(item(), "alias", "😀".repeat(200)));
        assert!(!validate(item(), "alias", "a".repeat(201)));
        assert!(!validate(item(), "alias", "alias\u{7f}".to_owned()));

        assert!(validate(
            item(),
            "hostname",
            format!("{}aa", "你".repeat(66))
        ));
        assert!(!validate(
            item(),
            "hostname",
            format!("{}é", "a".repeat(199))
        ));
        assert!(!validate(item(), "hostname", "host\n".to_owned()));

        assert!(validate(item(), "os", format!("{}a", "你".repeat(33))));
        assert!(!validate(item(), "os", format!("{}é", "a".repeat(99))));
        assert!(!validate(item(), "os", "os\u{85}".to_owned()));

        let mut shared = item();
        shared["source"] = json!("shared");
        shared["permission"] = json!("view_only");
        shared["share_id"] = json!(42);
        shared["shared_by_user_id"] = json!(7);
        shared["shared_by_username"] = json!("😀".repeat(100));
        let parsed: AddressBookItem = serde_json::from_value(shared.clone()).unwrap();
        assert!(parsed.validate().is_ok());
        for username in [String::new(), "😀".repeat(101), "alice\n".to_owned()] {
            shared["shared_by_username"] = json!(username);
            let parsed: AddressBookItem = serde_json::from_value(shared.clone()).unwrap();
            assert!(parsed.validate().is_err());
        }
    }

    #[test]
    fn future_cursor_reset_allows_empty_zero_baseline() {
        let body = json!({
            "mode": "delta",
            "ab_ver": 0,
            "next_ab_ver": 0,
            "changes": [],
            "page_size": 50,
            "has_more": false,
            "reset_required": true
        });
        let parsed = AddressBookDelta::parse(&body.to_string(), 9).unwrap();
        assert!(parsed.needs_refresh(9));
    }

    #[test]
    fn non_reset_response_cannot_move_cursor_backwards() {
        let body = json!({
            "mode": "delta",
            "ab_ver": 3,
            "next_ab_ver": 3,
            "changes": [],
            "page_size": 50,
            "has_more": false,
            "reset_required": false
        });
        assert!(AddressBookDelta::parse(&body.to_string(), 9).is_err());
    }

    #[test]
    fn poll_jitter_is_stable_spread_and_bounded() {
        let first = stable_poll_jitter("100001", "instance-a");
        assert_eq!(first, stable_poll_jitter("100001", "instance-a"));
        assert_eq!(
            poll_interval_for_identity("100001", "instance-a"),
            POLL_BASE_INTERVAL + first
        );

        let samples = (0..32)
            .map(|index| stable_poll_jitter("100001", &format!("instance-{index}")))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(samples.len() > 1, "不同实例应分散轮询时间");
        assert!(samples.iter().all(|jitter| *jitter <= POLL_JITTER_BOUND));
        assert!(samples.iter().all(|jitter| {
            let interval = POLL_BASE_INTERVAL + *jitter;
            interval >= POLL_BASE_INTERVAL && interval <= POLL_BASE_INTERVAL + POLL_JITTER_BOUND
        }));
    }
}
