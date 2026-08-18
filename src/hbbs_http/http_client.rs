use hbb_common::{
    anyhow::{anyhow, Context},
    async_recursion::async_recursion,
    config::{Config, Socks5Server},
    log::{self, info},
    proxy::{Proxy, ProxyScheme},
    tls::{
        get_cached_tls_accept_invalid_cert, get_cached_tls_type, is_plain, upsert_tls_cache,
        TlsType,
    },
    ResultType,
};
use reqwest::{blocking::Client as SyncClient, Client as AsyncClient};
use url::{Host, Url};

macro_rules! configure_http_client {
    ($builder:expr, $tls_type:expr, $danger_accept_invalid_cert:expr, $Client: ty) => {{
        // https://github.com/rustdesk/rustdesk/issues/11569
        // https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.no_proxy
        let mut builder = $builder.no_proxy();

        match $tls_type {
            TlsType::Plain => {}
            TlsType::NativeTls => {
                builder = builder.use_native_tls();
                if $danger_accept_invalid_cert {
                    builder = builder.danger_accept_invalid_certs(true);
                }
            }
            TlsType::Rustls => {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                match hbb_common::verifier::client_config($danger_accept_invalid_cert) {
                    Ok(client_config) => {
                        builder = builder.use_preconfigured_tls(client_config);
                    }
                    Err(e) => {
                        hbb_common::log::error!("Failed to get client config: {}", e);
                    }
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                {
                    builder = builder.use_rustls_tls();
                    if $danger_accept_invalid_cert {
                        builder = builder.danger_accept_invalid_certs(true);
                    }
                }
            }
        }

        let client = if let Some(conf) = Config::get_socks() {
            let proxy_result = Proxy::from_conf(&conf, None);

            match proxy_result {
                Ok(proxy) => {
                    let proxy_setup = match &proxy.intercept {
                        ProxyScheme::Http { host, .. } => {
                            reqwest::Proxy::all(format!("http://{}", host))
                        }
                        ProxyScheme::Https { host, .. } => {
                            reqwest::Proxy::all(format!("https://{}", host))
                        }
                        ProxyScheme::Socks5 { addr, .. } => {
                            reqwest::Proxy::all(&format!("socks5://{}", addr))
                        }
                    };

                    match proxy_setup {
                        Ok(mut p) => {
                            if let Some(auth) = proxy.intercept.maybe_auth() {
                                if !auth.username().is_empty() && !auth.password().is_empty() {
                                    p = p.basic_auth(auth.username(), auth.password());
                                }
                            }
                            builder = builder.proxy(p);
                            builder.build().unwrap_or_else(|e| {
                                info!("Failed to create a proxied client: {}", e);
                                <$Client>::new()
                            })
                        }
                        Err(e) => {
                            info!("Failed to set up proxy: {}", e);
                            <$Client>::new()
                        }
                    }
                }
                Err(e) => {
                    info!("Failed to configure proxy: {}", e);
                    <$Client>::new()
                }
            }
        } else {
            builder.build().unwrap_or_else(|e| {
                info!("Failed to create a client: {}", e);
                <$Client>::new()
            })
        };

        client
    }};
}

macro_rules! configure_strict_http_client {
    ($builder:expr, $proxy:expr) => {{
        let mut builder = $builder
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let client_config = hbb_common::verifier::client_config(false)
                .map_err(|error| anyhow!("Failed to configure strict mobile TLS: {error}"))?;
            builder = builder.use_preconfigured_tls(client_config);
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            builder = builder.use_rustls_tls();
        }

        if let Some(conf) = $proxy {
            let proxy = Proxy::from_conf(&conf, None)
                .map_err(|_| anyhow!("Failed to configure strict proxy"))?;
            let proxy_setup = match &proxy.intercept {
                ProxyScheme::Http { host, .. } => reqwest::Proxy::all(format!("http://{host}")),
                ProxyScheme::Https { host, .. } => reqwest::Proxy::all(format!("https://{host}")),
                ProxyScheme::Socks5 { addr, .. } => reqwest::Proxy::all(format!("socks5://{addr}")),
            }
            .context("Failed to build strict proxy")?;
            let proxy_setup = if let Some(auth) = proxy.intercept.maybe_auth() {
                if !auth.username().is_empty() && !auth.password().is_empty() {
                    proxy_setup.basic_auth(auth.username(), auth.password())
                } else {
                    proxy_setup
                }
            } else {
                proxy_setup
            };
            builder = builder.proxy(proxy_setup);
        }

        builder
            .build()
            .context("Failed to build strict HTTP client")
    }};
}

pub fn create_http_client(tls_type: TlsType, danger_accept_invalid_cert: bool) -> SyncClient {
    let builder = SyncClient::builder();
    configure_http_client!(builder, tls_type, danger_accept_invalid_cert, SyncClient)
}

pub fn create_http_client_async(
    tls_type: TlsType,
    danger_accept_invalid_cert: bool,
) -> AsyncClient {
    let builder = AsyncClient::builder();
    configure_http_client!(builder, tls_type, danger_accept_invalid_cert, AsyncClient)
}

/// 为可能包含凭据或敏感请求体的调用构造客户端。
///
/// 此路径不读取兼容 TLS 缓存，不接受无效证书，不跟随重定向，
/// 远程 HTTPS 保留已配置的代理，数值 loopback HTTP 始终直连。
pub fn create_strict_http_client(target_url: &str) -> ResultType<SyncClient> {
    create_strict_http_client_with_proxy(target_url, Config::get_socks())
}

/// [`create_strict_http_client`] 的异步版本。
pub fn create_strict_http_client_async(target_url: &str) -> ResultType<AsyncClient> {
    configure_strict_http_client!(
        AsyncClient::builder(),
        strict_proxy_for_target(target_url, Config::get_socks())
    )
}

fn create_strict_http_client_with_proxy(
    target_url: &str,
    configured_proxy: Option<Socks5Server>,
) -> ResultType<SyncClient> {
    configure_strict_http_client!(
        SyncClient::builder(),
        strict_proxy_for_target(target_url, configured_proxy)
    )
}

fn strict_proxy_for_target(
    target_url: &str,
    configured_proxy: Option<Socks5Server>,
) -> Option<Socks5Server> {
    let bypass = Url::parse(target_url).ok().is_some_and(|url| {
        url.scheme() == "http"
            && match url.host() {
                Some(Host::Ipv4(address)) => address.is_loopback(),
                Some(Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            }
    });
    if bypass {
        None
    } else {
        configured_proxy
    }
}

pub fn get_url_for_tls<'a>(url: &'a str, proxy_conf: &'a Option<Socks5Server>) -> &'a str {
    if is_plain(url) {
        if let Some(conf) = proxy_conf {
            if conf.proxy.starts_with("https://") {
                return &conf.proxy;
            }
        }
    }
    url
}

pub fn create_http_client_with_url(url: &str) -> SyncClient {
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url);
    let is_tls_type_cached = tls_type.is_some();
    let tls_type = tls_type.unwrap_or(TlsType::Rustls);
    let tls_danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url);
    create_http_client_with_url_(
        url,
        tls_url,
        tls_type,
        is_tls_type_cached,
        tls_danger_accept_invalid_cert,
        tls_danger_accept_invalid_cert,
    )
}

fn create_http_client_with_url_(
    url: &str,
    tls_url: &str,
    tls_type: TlsType,
    is_tls_type_cached: bool,
    danger_accept_invalid_cert: Option<bool>,
    original_danger_accept_invalid_cert: Option<bool>,
) -> SyncClient {
    let mut client = create_http_client(tls_type, danger_accept_invalid_cert.unwrap_or(false));
    if is_tls_type_cached && original_danger_accept_invalid_cert.is_some() {
        return client;
    }
    if let Err(e) = client.head(url).send() {
        if e.is_request() {
            match (tls_type, is_tls_type_cached, danger_accept_invalid_cert) {
                (TlsType::Rustls, _, None) => {
                    log::warn!(
                        "Failed to connect to server {} with rustls-tls: {:?}, trying accept invalid cert",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_cert,
                    );
                }
                (TlsType::Rustls, false, Some(_)) => {
                    log::warn!(
                        "Failed to connect to server {} with rustls-tls: {:?}, trying native-tls",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        TlsType::NativeTls,
                        is_tls_type_cached,
                        original_danger_accept_invalid_cert,
                        original_danger_accept_invalid_cert,
                    );
                }
                (TlsType::NativeTls, _, None) => {
                    log::warn!(
                        "Failed to connect to server {} with native-tls: {:?}, trying accept invalid cert",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_cert,
                    );
                }
                _ => {
                    log::error!(
                        "Failed to connect to server {} with {:?}, err: {:?}.",
                        tls_url,
                        tls_type,
                        e
                    );
                }
            }
        } else {
            log::warn!(
                "Failed to connect to server {} with {:?}, err: {}.",
                tls_url,
                tls_type,
                e
            );
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_cache(
            tls_url,
            tls_type,
            danger_accept_invalid_cert.unwrap_or(false),
        );
    }
    client
}

pub async fn create_http_client_async_with_url(url: &str) -> AsyncClient {
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url);
    let is_tls_type_cached = tls_type.is_some();
    let tls_type = tls_type.unwrap_or(TlsType::Rustls);
    let danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url);
    create_http_client_async_with_url_(
        url,
        tls_url,
        tls_type,
        is_tls_type_cached,
        danger_accept_invalid_cert,
        danger_accept_invalid_cert,
    )
    .await
}

#[async_recursion]
async fn create_http_client_async_with_url_(
    url: &str,
    tls_url: &str,
    tls_type: TlsType,
    is_tls_type_cached: bool,
    danger_accept_invalid_cert: Option<bool>,
    original_danger_accept_invalid_cert: Option<bool>,
) -> AsyncClient {
    let mut client =
        create_http_client_async(tls_type, danger_accept_invalid_cert.unwrap_or(false));
    if is_tls_type_cached && original_danger_accept_invalid_cert.is_some() {
        return client;
    }
    if let Err(e) = client.head(url).send().await {
        match (tls_type, is_tls_type_cached, danger_accept_invalid_cert) {
            (TlsType::Rustls, _, None) => {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {:?}, trying accept invalid cert",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    tls_type,
                    is_tls_type_cached,
                    Some(true),
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            (TlsType::Rustls, false, Some(_)) => {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {:?}, trying native-tls",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    TlsType::NativeTls,
                    is_tls_type_cached,
                    original_danger_accept_invalid_cert,
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            (TlsType::NativeTls, _, None) => {
                log::warn!(
                    "Failed to connect to server {} with native-tls: {:?}, trying accept invalid cert",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    tls_type,
                    is_tls_type_cached,
                    Some(true),
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            _ => {
                log::error!(
                    "Failed to connect to server {} with {:?}, err: {:?}.",
                    tls_url,
                    tls_type,
                    e
                );
            }
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_cache(
            tls_url,
            tls_type,
            danger_accept_invalid_cert.unwrap_or(false),
        );
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{ErrorKind, Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn strict_loopback_http_bypasses_configured_proxy_and_keeps_bearer_local() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        proxy.set_nonblocking(true).unwrap();
        let target_url = format!("http://{}/credential", target.local_addr().unwrap());
        let configured_proxy = Socks5Server {
            proxy: format!("http://{}", proxy.local_addr().unwrap()),
            username: String::new(),
            password: String::new(),
        };
        let client =
            create_strict_http_client_with_proxy(&target_url, Some(configured_proxy)).unwrap();
        let request_url = target_url.clone();
        let request = thread::spawn(move || {
            client
                .get(request_url)
                .bearer_auth("loopback-secret")
                .timeout(Duration::from_secs(2))
                .send()
                .map(|response| response.status().as_u16())
        });

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut target_request = None;
        let mut proxy_seen = false;
        while Instant::now() < deadline {
            match target.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = [0_u8; 8192];
                    let length = stream.read(&mut bytes).unwrap();
                    target_request = Some(String::from_utf8_lossy(&bytes[..length]).into_owned());
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("目标监听失败：{error}"),
            }
            match proxy.accept() {
                Ok((mut stream, _)) => {
                    proxy_seen = true;
                    stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("代理监听失败：{error}"),
            }
            thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(request.join().unwrap().unwrap(), 204);
        assert!(!proxy_seen, "loopback strict 请求不得连接配置代理");
        let target_request = target_request.expect("loopback 目标应收到 strict 请求");
        assert!(target_request
            .to_ascii_lowercase()
            .contains("authorization: bearer loopback-secret"));
        assert!(matches!(
            proxy.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn strict_remote_https_keeps_configured_proxy() {
        let proxy = Socks5Server {
            proxy: "http://127.0.0.1:3128".to_owned(),
            username: String::new(),
            password: String::new(),
        };
        assert_eq!(
            strict_proxy_for_target("https://api.example.com", Some(proxy.clone())),
            Some(proxy)
        );
        assert!(
            strict_proxy_for_target("http://[::1]:21114", Some(Socks5Server::default())).is_none()
        );
    }
}
