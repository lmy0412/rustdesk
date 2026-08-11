#![cfg(not(any(feature = "flutter", feature = "cli")))]

use librustdesk::ui::{
    issue9_sciter_audit_is_fail_closed, issue9_sciter_generic_headers_are_allowed,
    issue9_sciter_operation_is_allowed, issue9_sciter_option_key_is_allowed,
    issue9_sciter_safe_summary_json,
};

#[test]
fn issue9_sciter_auth只开放封闭业务操作() {
    for operation in ["current_user", "address_book_get", "address_book_update"] {
        assert!(issue9_sciter_operation_is_allowed(operation));
    }
    for operation in [
        "",
        "login",
        "logout",
        "address_book_v2",
        "https://example.com/api/currentUser",
    ] {
        assert!(!issue9_sciter_operation_is_allowed(operation));
    }
}

#[test]
fn issue9_sciter_auth通用http拒绝裸请求头() {
    assert!(issue9_sciter_generic_headers_are_allowed(""));
    assert!(issue9_sciter_generic_headers_are_allowed(" \t\r\n"));
    assert!(!issue9_sciter_generic_headers_are_allowed(
        "Authorization: Bearer sentinel"
    ));
    assert!(!issue9_sciter_generic_headers_are_allowed(
        "Cookie: sentinel"
    ));
}

#[test]
fn issue9_sciter_auth通用配置桥拒绝认证游标和pending键() {
    for key in [
        "access_token",
        "user-info",
        "AUTH_STATE",
        "auth_cursor",
        "address-book-cursor",
        "pending",
        "pending_logout_ticket",
        "api-server",
        "custom-rendezvous-server",
        "relay-server",
        "key",
    ] {
        assert!(!issue9_sciter_option_key_is_allowed(key), "{key}");
    }
    for key in ["lang", "selected-tags", "audio-input", "proxy-url"] {
        assert!(issue9_sciter_option_key_is_allowed(key), "{key}");
    }
}

#[test]
fn issue9_sciter_auth安全摘要不含凭证和认证证明() {
    let value: serde_json::Value =
        serde_json::from_str(&issue9_sciter_safe_summary_json()).unwrap();
    assert_eq!(value["id"], 7);
    assert_eq!(value["name"], "alice");
    assert_eq!(value["display_name"], "Alice");
    assert!(value.get("access_token").is_none());
    assert!(value.get("verifier").is_none());
    assert!(value.get("email").is_none());
    assert!(value.get("note").is_none());
    let serialized = value.to_string();
    assert!(!serialized.contains("private-verifier"));
    assert!(!serialized.contains("private@example.com"));
    assert!(!serialized.contains("private-note"));
}

#[test]
fn issue9_sciter_auth_tis只调用typed登录会话和注销桥() {
    let common = include_str!("../src/ui/common.tis");
    let index = include_str!("../src/ui/index.tis");
    let address_book = include_str!("../src/ui/ab.tis");
    let ui_bridge = include_str!("../src/ui.rs");
    let ui_interface = include_str!("../src/ui_interface.rs");

    assert!(common.contains(
        "function sciterAuthLogin(params, _onSuccess, _onError, nativeAttempt = \"\", parentJobId = \"\")"
    ));
    assert!(common.contains("JSON.stringify(params), nativeAttempt || \"\", parentJobId || \"\""));
    assert!(common.contains("handler.get_sciter_auth_job_status(jobId)"));
    assert!(common.contains("handler.start_sciter_auth_request"));
    assert!(common.contains("headers != \"\""));
    assert!(index.contains("sciterAuthLogin("));
    assert!(index.contains("var name = res.username || '';"));
    assert!(index.contains("var pass = res.password || '';"));
    assert!(!index.contains("(res.username || '').trim()"));
    assert!(!index.contains("(res.password || '').trim()"));
    assert!(index.contains("!(last_msg.user.name || '')"));
    assert!(!index.contains("(last_msg.user.name || '').trim()"));
    assert!(index.contains("sciterAuthRequest(\"current_user\""));
    assert!(index.contains("handler.start_sciter_auth_logout()"));
    assert!(index.contains("const nativeAttempt = last_msg.native_attempt || '';"));
    assert!(index.contains("var nativeJobId = last_msg.native_job_id || '';"));
    assert!(index.contains("handler.cancel_sciter_auth_attempt(nativeAttempt)"));
    assert!(index.contains("nativeAttempt,"));
    assert!(index.contains("if (nextJobId) nativeJobId = nextJobId;"));
    assert!(!index.contains("native_attempt:"));
    assert!(!index.contains("set_local_option(\"native_"));
    assert!(!index.contains("JSON.parse(nativeAttempt"));
    assert!(ui_bridge.contains("fn start_sciter_auth_login(String, String, String);"));
    assert!(ui_bridge.contains("fn cancel_sciter_auth_attempt(String);"));
    assert!(ui_bridge.contains("fn get_sciter_auth_job_status(String);"));
    assert!(ui_interface.contains("\"native_attempt\": native_attempt"));
    assert!(ui_interface.contains("\"native_job_id\": job_id.to_string()"));
    assert!(index.contains("handler.set_server_config("));
    assert!(address_book.contains("sciterAuthRequest(\"address_book_get\""));
    assert!(address_book.contains("sciterAuthRequest(\"address_book_update\""));

    for source in [index, address_book] {
        assert!(!source.contains("access_token"));
        assert!(!source.contains("Authorization"));
        assert!(!source.contains("Bearer"));
        assert!(!source.contains("getHttpHeaders"));
    }
}

#[test]
fn issue9_sciter_auth_remote_session审计明确fail_closed() {
    assert!(issue9_sciter_audit_is_fail_closed());
    let source = include_str!("../src/ui_session_interface.rs");
    assert!(!source.contains("LocalConfig::get_option(\"access_token\")"));
    assert!(source.contains("审计备注不可用：主界面授权已失效或本地安全通道已断开"));
}
