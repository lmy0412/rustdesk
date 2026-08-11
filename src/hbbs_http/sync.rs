use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(not(any(target_os = "ios")))]
use crate::{ui_interface::get_builtin_option, Connection};
use hbb_common::{
    anyhow::{anyhow, Context},
    config::{self, keys, Config, LocalConfig},
    log,
    tokio::{self, sync::broadcast, time::Instant},
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

const TIME_HEARTBEAT: Duration = Duration::from_secs(15);
const UPLOAD_SYSINFO_TIMEOUT: Duration = Duration::from_secs(120);
const TIME_CONN: Duration = Duration::from_secs(3);
const STRICT_REPROBE_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(not(any(target_os = "ios")))]
lazy_static::lazy_static! {
    static ref SENDER : Mutex<broadcast::Sender<Vec<i32>>> = Mutex::new(start_hbbs_sync());
    static ref PRO: Arc<Mutex<bool>> = Default::default();
}

#[cfg(not(any(target_os = "ios")))]
pub fn start() {
    let _sender = SENDER.lock().unwrap();
}

#[cfg(not(target_os = "ios"))]
pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
    SENDER.lock().unwrap().subscribe()
}

#[cfg(not(any(target_os = "ios")))]
fn start_hbbs_sync() -> broadcast::Sender<Vec<i32>> {
    let (tx, _rx) = broadcast::channel::<Vec<i32>>(16);
    std::thread::spawn(move || start_hbbs_sync_async());
    return tx;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrategyOptions {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config_options: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

struct InfoUploaded {
    uploaded: bool,
    url: String,
    transport: ServiceTransport,
    last_uploaded: Option<Instant>,
    id: String,
    username: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceTransport {
    NoSecretMinimal,
    LegacySensitiveStrict,
}

#[derive(Debug)]
struct ServiceTransportState {
    url: String,
    active: ServiceTransport,
    next_strict_probe: Option<Instant>,
}

impl Default for ServiceTransportState {
    fn default() -> Self {
        Self {
            url: String::new(),
            active: ServiceTransport::NoSecretMinimal,
            next_strict_probe: None,
        }
    }
}

impl ServiceTransportState {
    fn transport_for_tick(&mut self, url: &str, now: Instant) -> (ServiceTransport, bool) {
        let preferred = service_transport_for_url(url);
        if self.url != url {
            let changed = !self.url.is_empty() || self.active != preferred;
            self.url = url.to_owned();
            self.active = preferred;
            self.next_strict_probe = None;
            return (self.active, changed);
        }

        if preferred == ServiceTransport::NoSecretMinimal {
            let changed = self.active != ServiceTransport::NoSecretMinimal;
            self.active = ServiceTransport::NoSecretMinimal;
            self.next_strict_probe = None;
            return (self.active, changed);
        }

        if self.active == ServiceTransport::NoSecretMinimal
            && self
                .next_strict_probe
                .is_some_and(|deadline| now >= deadline)
        {
            self.active = ServiceTransport::LegacySensitiveStrict;
            self.next_strict_probe = None;
            return (self.active, true);
        }

        (self.active, false)
    }

    fn mark_strict_failure(&mut self, url: &str, now: Instant) -> bool {
        if self.url != url || self.active != ServiceTransport::LegacySensitiveStrict {
            return false;
        }
        self.active = ServiceTransport::NoSecretMinimal;
        self.next_strict_probe = Some(now + STRICT_REPROBE_INTERVAL);
        true
    }
}

impl Default for InfoUploaded {
    fn default() -> Self {
        Self {
            uploaded: false,
            url: "".to_owned(),
            transport: ServiceTransport::NoSecretMinimal,
            last_uploaded: None,
            id: "".to_owned(),
            username: None,
        }
    }
}

impl InfoUploaded {
    fn uploaded(url: String, transport: ServiceTransport, id: String, username: String) -> Self {
        Self {
            uploaded: true,
            url,
            transport,
            last_uploaded: None,
            id,
            username: Some(username),
        }
    }
}

#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn start_hbbs_sync_async() {
    crate::hbbs_http::auth_binding::scrub_legacy_auth_mirror();
    let mut interval = crate::rustdesk_interval(tokio::time::interval_at(
        Instant::now() + TIME_CONN,
        TIME_CONN,
    ));
    let mut last_sent: Option<Instant> = None;
    let mut info_uploaded = InfoUploaded::default();
    let mut sysinfo_ver = "".to_owned();
    let mut transport_state = ServiceTransportState::default();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let url = heartbeat_url();
                let id = Config::get_id();
                if url.is_empty() {
                    *PRO.lock().unwrap() = false;
                    continue;
                }
                let (transport, transport_changed) =
                    transport_state.transport_for_tick(&url, Instant::now());
                if transport_changed {
                    reset_transport_upload_state(
                        &mut info_uploaded,
                        &mut sysinfo_ver,
                        transport,
                    );
                    *PRO.lock().unwrap() = false;
                }
                if config::option2bool("stop-service", &Config::get_option("stop-service")) {
                    continue;
                }
                let conns = Connection::alive_conns();
                if info_uploaded.uploaded
                    && (url != info_uploaded.url
                        || id != info_uploaded.id
                        || transport != info_uploaded.transport)
                {
                    info_uploaded.uploaded = false;
                    info_uploaded.last_uploaded = None;
                    *PRO.lock().unwrap() = false;
                }
                // For Windows:
                // We can't skip uploading sysinfo when the username is empty, because the username may
                // always be empty before login. We also need to upload the other sysinfo info.
                //
                // https://github.com/rustdesk/rustdesk/discussions/8031
                // We still need to check the username after uploading sysinfo, because
                // 1. The username may be empty when logining in, and it can be fetched after a while.
                //    In this case, we need to upload sysinfo again.
                // 2. The username may be changed after uploading sysinfo, and we need to upload sysinfo again.
                //
                // The Windows session will switch to the last user session before the restart,
                // so it may be able to get the username before login.
                // But strangely, sometimes we can get the username before login,
                // we may not be able to get the username before login after the next restart.
                let mut v = match transport {
                    ServiceTransport::NoSecretMinimal => minimal_sysinfo(&id),
                    ServiceTransport::LegacySensitiveStrict => crate::get_sysinfo(),
                };
                let sys_username = if transport == ServiceTransport::LegacySensitiveStrict {
                    v["username"].as_str().unwrap_or_default().to_string()
                } else {
                    String::new()
                };
                // Though the username comparison is only necessary on Windows,
                // we still keep the comparison on other platforms for consistency.
                let need_upload = (!info_uploaded.uploaded || info_uploaded.username.as_ref() != Some(&sys_username)) &&
                    info_uploaded.last_uploaded.map(|x| x.elapsed() >= UPLOAD_SYSINFO_TIMEOUT).unwrap_or(true);
                if need_upload {
                    v["version"] = json!(crate::VERSION);
                    v["id"] = json!(id);
                    v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                    if transport == ServiceTransport::LegacySensitiveStrict {
                        add_legacy_sensitive_sysinfo_fields(&mut v);
                    }
                    let v = v.to_string();
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(url.as_bytes());
                    hasher.update(v.as_bytes());
                    let res = hasher.finalize();
                    let hash = hbb_common::base64::encode(&res[..]);
                    let status_suffix = transport.status_suffix();
                    let hash_key = format!("sysinfo_hash_{status_suffix}");
                    let ver_key = format!("sysinfo_ver_{status_suffix}");
                    let old_hash = config::Status::get(&hash_key);
                    let ver = config::Status::get(&ver_key);
                    if hash == old_hash {
                        let samever = match service_post(
                            transport,
                            &sibling_endpoint(&url, "sysinfo_ver").unwrap_or_default(),
                            String::new(),
                        ).await {
                            Ok(x) => {
                                sysinfo_ver = x.clone();
                                *PRO.lock().unwrap() = true;
                                x == ver
                            }
                            _ if transport_state.mark_strict_failure(&url, Instant::now()) => {
                                reset_transport_upload_state(
                                    &mut info_uploaded,
                                    &mut sysinfo_ver,
                                    ServiceTransport::NoSecretMinimal,
                                );
                                *PRO.lock().unwrap() = false;
                                continue;
                            }
                            _ => false,
                        };
                        if samever {
                            info_uploaded = InfoUploaded::uploaded(
                                url.clone(),
                                transport,
                                id.clone(),
                                sys_username,
                            );
                            log::info!("sysinfo not changed, skip upload");
                            continue;
                        }
                    }
                    let sysinfo_url = sibling_endpoint(&url, "sysinfo").unwrap_or_default();
                    match service_post(transport, &sysinfo_url, v).await {
                        Ok(x)  => {
                            if x == "SYSINFO_UPDATED" {
                                info_uploaded = InfoUploaded::uploaded(
                                    url.clone(),
                                    transport,
                                    id.clone(),
                                    sys_username,
                                );
                                log::info!("sysinfo updated");
                                if !hash.is_empty() {
                                    config::Status::set(&hash_key, hash);
                                    config::Status::set(&ver_key, sysinfo_ver.clone());
                                }
                                *PRO.lock().unwrap() = true;
                            } else if x == "ID_NOT_FOUND" {
                                info_uploaded.last_uploaded = None; // next heartbeat will upload sysinfo again
                            } else {
                                info_uploaded.last_uploaded = Some(Instant::now());
                            }
                        }
                        _ if transport_state.mark_strict_failure(&url, Instant::now()) => {
                            reset_transport_upload_state(
                                &mut info_uploaded,
                                &mut sysinfo_ver,
                                ServiceTransport::NoSecretMinimal,
                            );
                            *PRO.lock().unwrap() = false;
                            continue;
                        }
                        _ => {
                            info_uploaded.last_uploaded = Some(Instant::now());
                        }
                    }
                }
                if conns.is_empty() && last_sent.map(|x| x.elapsed() < TIME_HEARTBEAT).unwrap_or(false) {
                    continue;
                }
                last_sent = Some(Instant::now());
                let mut v = minimal_heartbeat(&id);
                let modified_at =
                    LocalConfig::get_option("strategy_timestamp").parse::<i64>().unwrap_or(0);
                if transport == ServiceTransport::LegacySensitiveStrict {
                    if !conns.is_empty() {
                        v["conns"] = json!(conns);
                    }
                    v["modified_at"] = json!(modified_at);
                }
                match service_post(transport, &url, v.to_string()).await {
                    Ok(s) => {
                        if transport == ServiceTransport::NoSecretMinimal {
                            continue;
                        }
                        if let Ok(mut rsp) = serde_json::from_str::<HashMap::<&str, Value>>(&s) {
                            if rsp.remove("sysinfo").is_some() {
                                info_uploaded.uploaded = false;
                                let hash_key =
                                    format!("sysinfo_hash_{}", transport.status_suffix());
                                config::Status::set(&hash_key, "".to_owned());
                                log::info!("sysinfo required to forcely update");
                            }
                            if let Some(conns)  = rsp.remove("disconnect") {
                                    if let Ok(conns) = serde_json::from_value::<Vec<i32>>(conns) {
                                        SENDER.lock().unwrap().send(conns).ok();
                                    }
                            }
                            if let Some(rsp_modified_at) = rsp.remove("modified_at") {
                                if let Ok(rsp_modified_at) = serde_json::from_value::<i64>(rsp_modified_at) {
                                    if rsp_modified_at != modified_at {
                                        LocalConfig::set_option("strategy_timestamp".to_string(), rsp_modified_at.to_string());
                                    }
                                }
                            }
                            if let Some(strategy) = rsp.remove("strategy") {
                                if let Ok(strategy) = serde_json::from_value::<StrategyOptions>(strategy) {
                                    log::info!("strategy updated");
                                    handle_config_options(strategy.config_options);
                                }
                            }
                        }
                    }
                    Err(_) if transport_state.mark_strict_failure(&url, Instant::now()) => {
                        reset_transport_upload_state(
                            &mut info_uploaded,
                            &mut sysinfo_ver,
                            ServiceTransport::NoSecretMinimal,
                        );
                        *PRO.lock().unwrap() = false;
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

fn reset_transport_upload_state(
    info_uploaded: &mut InfoUploaded,
    sysinfo_ver: &mut String,
    next_transport: ServiceTransport,
) {
    info_uploaded.uploaded = false;
    info_uploaded.last_uploaded = None;
    sysinfo_ver.clear();
    config::Status::set(
        &format!("sysinfo_hash_{}", next_transport.status_suffix()),
        String::new(),
    );
    config::Status::set(
        &format!("sysinfo_ver_{}", next_transport.status_suffix()),
        String::new(),
    );
}

impl ServiceTransport {
    fn status_suffix(self) -> &'static str {
        match self {
            Self::NoSecretMinimal => "minimal",
            Self::LegacySensitiveStrict => "legacy_sensitive_strict",
        }
    }
}

fn service_transport_for_url(url: &str) -> ServiceTransport {
    if crate::hbbs_http::auth_binding::validate_strict_target(url).is_ok() {
        ServiceTransport::LegacySensitiveStrict
    } else {
        ServiceTransport::NoSecretMinimal
    }
}

fn minimal_sysinfo(id: &str) -> Value {
    let source = crate::get_sysinfo();
    let hostname = source
        .get("hostname")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let os = source.get("os").and_then(Value::as_str).unwrap_or_default();
    json!({
        "id": id,
        "uuid": crate::encode64(hbb_common::get_uuid()),
        "hostname": hostname,
        "os": os,
        "version": crate::VERSION,
    })
}

fn minimal_heartbeat(id: &str) -> Value {
    json!({
        "id": id,
        "uuid": crate::encode64(hbb_common::get_uuid()),
        "ver": hbb_common::get_version_number(crate::VERSION),
    })
}

fn add_legacy_sensitive_sysinfo_fields(value: &mut Value) {
    for (key, option_value) in [
        (
            keys::OPTION_PRESET_ADDRESS_BOOK_NAME,
            Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NAME),
        ),
        (
            keys::OPTION_PRESET_ADDRESS_BOOK_TAG,
            Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_TAG),
        ),
        (
            keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS,
            Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS),
        ),
        (
            keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD,
            Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD),
        ),
        (
            keys::OPTION_PRESET_ADDRESS_BOOK_NOTE,
            Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NOTE),
        ),
        (
            keys::OPTION_PRESET_USERNAME,
            get_builtin_option(keys::OPTION_PRESET_USERNAME),
        ),
        (
            keys::OPTION_PRESET_STRATEGY_NAME,
            get_builtin_option(keys::OPTION_PRESET_STRATEGY_NAME),
        ),
        (
            keys::OPTION_PRESET_DEVICE_GROUP_NAME,
            get_builtin_option(keys::OPTION_PRESET_DEVICE_GROUP_NAME),
        ),
    ] {
        if !option_value.is_empty() {
            value[key] = json!(option_value);
        }
    }
    let device_username = Config::get_option(keys::OPTION_PRESET_DEVICE_USERNAME);
    if !device_username.is_empty() {
        value["username"] = json!(device_username);
    }
    let device_name = Config::get_option(keys::OPTION_PRESET_DEVICE_NAME);
    if !device_name.is_empty() {
        value["hostname"] = json!(device_name);
    }
    let note = Config::get_option(keys::OPTION_PRESET_NOTE);
    if !note.is_empty() {
        value[keys::OPTION_PRESET_NOTE] = json!(note);
    }
}

async fn service_post(transport: ServiceTransport, url: &str, body: String) -> ResultType<String> {
    if url.is_empty() {
        return Err(anyhow!("服务端 API 地址无效"));
    }
    match transport {
        ServiceTransport::NoSecretMinimal => crate::post_request(url.to_owned(), body, "").await,
        ServiceTransport::LegacySensitiveStrict => {
            let response = crate::common::strict_http_request_no_bearer(
                crate::common::RequestSecurityClass::SensitiveNoBearerStrict,
                crate::common::StrictHttpRequest::new(
                    crate::common::StrictHttpMethod::Post,
                    url.to_owned(),
                )
                .json_body(body),
            )
            .await?;
            response.ensure_success().map(|response| response.body)
        }
    }
}

fn sibling_endpoint(url: &str, endpoint: &str) -> ResultType<String> {
    let mut parsed = Url::parse(url).context("服务端 API 地址无效")?;
    {
        let mut segments = parsed
            .path_segments_mut()
            .map_err(|_| anyhow!("服务端 API 地址不能作为层级路径"))?;
        segments.pop_if_empty();
        segments.pop();
        segments.push(endpoint);
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn heartbeat_url() -> String {
    heartbeat_url_for(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    )
}

fn heartbeat_url_for(api_server: String, custom_rendezvous_server: String) -> String {
    let url = crate::common::get_api_server(api_server, custom_rendezvous_server);
    if url.is_empty() {
        return "".to_owned();
    }
    api_endpoint(&url, "heartbeat").unwrap_or_default()
}

fn api_endpoint(base: &str, endpoint: &str) -> ResultType<String> {
    let mut url = Url::parse(base).context("API base 无效")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("API base 不能作为层级路径"))?;
        segments.pop_if_empty();
        segments.push("api");
        segments.push(endpoint);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn handle_config_options(config_options: HashMap<String, String>) {
    let mut options = Config::get_options();
    let default_settings = config::DEFAULT_SETTINGS.read().unwrap().clone();
    config_options
        .iter()
        .filter(|(key, _)| {
            let blocked = crate::hbbs_http::auth_binding::is_protected_auth_option(key)
                || crate::hbbs_http::auth_binding::is_server_authority_option(key);
            if blocked {
                log::warn!("忽略服务端策略中的受保护配置项: {}", key);
            }
            !blocked
        })
        .map(|(k, v)| {
            // Priority: user config > default advanced options.
            // Only when default advanced options are also empty, remove user option (fallback to built-in default);
            // otherwise insert an empty value so user config remains present.
            if v.is_empty() && default_settings.get(k).map_or("", |v| v).is_empty() {
                options.remove(k);
            } else {
                options.insert(k.to_string(), v.to_string());
            }
        })
        .count();
    Config::set_options(options);
}

#[allow(unused)]
#[cfg(not(any(target_os = "ios")))]
pub fn is_pro() -> bool {
    PRO.lock().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::{
        heartbeat_url_for, minimal_heartbeat, minimal_sysinfo, service_transport_for_url,
        sibling_endpoint, ServiceTransport, ServiceTransportState, STRICT_REPROBE_INTERVAL,
    };
    use hbb_common::tokio::time::Instant;
    use std::time::Duration;

    #[test]
    fn heartbeat_url_supports_public_and_custom_api_servers() {
        assert_eq!(
            heartbeat_url_for("https://admin.rustdesk.com".to_owned(), String::new()),
            "https://admin.rustdesk.com/api/heartbeat"
        );
        assert_eq!(
            heartbeat_url_for("https://self.example/base".to_owned(), String::new()),
            "https://self.example/base/api/heartbeat"
        );
    }

    #[test]
    fn endpoint_builder_preserves_base_paths_and_literal_heartbeat_hosts() {
        let heartbeat =
            heartbeat_url_for("https://heartbeat.example/base".to_owned(), String::new());
        assert_eq!(heartbeat, "https://heartbeat.example/base/api/heartbeat");
        assert_eq!(
            sibling_endpoint(&heartbeat, "sysinfo").unwrap(),
            "https://heartbeat.example/base/api/sysinfo"
        );
        assert_eq!(
            sibling_endpoint(&heartbeat, "sysinfo_ver").unwrap(),
            "https://heartbeat.example/base/api/sysinfo_ver"
        );
    }

    #[test]
    fn remote_http_is_always_minimal() {
        assert_eq!(
            service_transport_for_url("http://example.com/api/heartbeat"),
            ServiceTransport::NoSecretMinimal
        );
        assert_eq!(
            service_transport_for_url("https://example.com/api/heartbeat"),
            ServiceTransport::LegacySensitiveStrict
        );
        assert_eq!(
            service_transport_for_url("http://127.0.0.1:21114/api/heartbeat"),
            ServiceTransport::LegacySensitiveStrict
        );
    }

    #[test]
    fn minimal_payloads_have_a_closed_key_set() {
        let sysinfo = minimal_sysinfo("123");
        let heartbeat = minimal_heartbeat("123");
        let mut sysinfo_keys = sysinfo
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut heartbeat_keys = heartbeat
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        sysinfo_keys.sort_unstable();
        heartbeat_keys.sort_unstable();
        assert_eq!(sysinfo_keys, ["hostname", "id", "os", "uuid", "version"]);
        assert_eq!(heartbeat_keys, ["id", "uuid", "ver"]);
    }

    #[test]
    fn strict_failure_falls_back_and_reprobes_on_a_bounded_schedule() {
        let url = "https://example.com/api/heartbeat";
        let start = Instant::now();
        let mut state = ServiceTransportState::default();

        assert_eq!(
            state.transport_for_tick(url, start),
            (ServiceTransport::LegacySensitiveStrict, true)
        );
        assert!(state.mark_strict_failure(url, start));
        assert_eq!(
            state.transport_for_tick(
                url,
                start + STRICT_REPROBE_INTERVAL - Duration::from_millis(1)
            ),
            (ServiceTransport::NoSecretMinimal, false)
        );
        assert_eq!(
            state.transport_for_tick(url, start + STRICT_REPROBE_INTERVAL),
            (ServiceTransport::LegacySensitiveStrict, true)
        );
    }

    #[test]
    fn remote_http_never_reprobes_with_sensitive_transport() {
        let url = "http://example.com/api/heartbeat";
        let start = Instant::now();
        let mut state = ServiceTransportState::default();

        assert_eq!(
            state.transport_for_tick(url, start),
            (ServiceTransport::NoSecretMinimal, false)
        );
        assert!(!state.mark_strict_failure(url, start));
        assert_eq!(
            state.transport_for_tick(url, start + STRICT_REPROBE_INTERVAL * 10),
            (ServiceTransport::NoSecretMinimal, false)
        );
    }
}
