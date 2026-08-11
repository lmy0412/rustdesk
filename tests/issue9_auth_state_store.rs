use librustdesk::hbbs_http::{
    auth_binding::{
        normalize_api_base, validate_target_against_base, AddressBookCapability, AuthBinding,
        AuthSafeUser, DeviceIdentitySnapshot,
    },
    auth_state_store::{AuthAuthorityAnchor, AuthStateStore},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const PROCESS_HELPER_ENV: &str = "RUSTDESK_ISSUE9_PROCESS_HELPER";
const PROCESS_HELPER_ROOT_ENV: &str = "RUSTDESK_ISSUE9_PROCESS_HELPER_ROOT";
const PROCESS_HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("rustdesk-issue9-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("应创建测试目录");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn anchor(root: &TestRoot) -> AuthAuthorityAnchor {
    AuthAuthorityAnchor::from_root_and_identity(root.path(), b"issue9-test-install")
        .expect("应创建测试 authority")
}

fn anchor_from_path(root: &Path) -> AuthAuthorityAnchor {
    AuthAuthorityAnchor::from_root_and_identity(root, b"issue9-test-install")
        .expect("应创建测试 authority")
}

struct HelperChild {
    child: Child,
}

impl HelperChild {
    fn spawn(root: &Path, action: &str) -> Self {
        let child = Command::new(std::env::current_exe().expect("应解析当前测试二进制"))
            .args([
                "--exact",
                "issue9_process_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROCESS_HELPER_ENV, action)
            .env(PROCESS_HELPER_ROOT_ENV, root)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("应启动 Issue9 helper 子进程");
        Self { child }
    }

    fn wait_success(mut self) {
        let deadline = Instant::now() + PROCESS_HELPER_TIMEOUT;
        loop {
            match self.child.try_wait().expect("应查询 helper 子进程状态") {
                Some(status) => {
                    assert!(status.success(), "helper 子进程应成功退出：{status}");
                    return;
                }
                None if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
                None => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("helper 子进程未在超时内退出");
                }
            }
        }
    }

    fn terminate(mut self) {
        self.child.kill().expect("应终止模拟崩溃的 helper 子进程");
        self.child.wait().expect("应回收 helper 子进程");
    }
}

impl Drop for HelperChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_path(path: &Path, description: &str) {
    let deadline = Instant::now() + PROCESS_HELPER_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    panic!("等待{description}超时");
}

#[test]
fn issue9_process_helper() {
    let Ok(action) = std::env::var(PROCESS_HELPER_ENV) else {
        return;
    };
    let root = PathBuf::from(
        std::env::var_os(PROCESS_HELPER_ROOT_ENV).expect("helper 必须收到测试根目录"),
    );
    let authority = anchor_from_path(&root);
    let store = AuthStateStore::open(authority).expect("helper 应取得 writer lifetime lock");
    let ready = root.join("helper.ready");

    match action.as_str() {
        "hold-writer-lock" => {
            fs::write(&ready, b"ready").expect("helper 应发布持锁就绪标记");
            wait_for_path(&root.join("helper.release"), "helper 释放标记");
            drop(store);
        }
        "crash-with-orphan-temp" => {
            fs::write(store.directory().join("state.process-crash.tmp"), b"orphan")
                .expect("helper 应写入不含秘密的孤立 temp");
            fs::write(&ready, b"ready").expect("helper 应发布崩溃前就绪标记");
            wait_for_path(&root.join("helper.never-release"), "模拟崩溃终止");
            drop(store);
        }
        other => panic!("未知 helper 动作：{other}"),
    }
}

fn safe_user(id: u64, name: &str) -> AuthSafeUser {
    AuthSafeUser {
        id: Some(id),
        name: name.to_owned(),
        display_name: name.to_owned(),
        avatar: String::new(),
        email: String::new(),
        note: String::new(),
        status: 1,
        is_admin: false,
        verifier: String::new(),
    }
}

#[test]
fn authority_anchor_is_stable_and_install_scoped() {
    let root = TestRoot::new("anchor");
    let first = AuthAuthorityAnchor::from_root_and_identity(root.path(), b"install-a")
        .expect("应创建 authority");
    let same = AuthAuthorityAnchor::from_root_and_identity(root.path(), b"install-a")
        .expect("应创建相同 authority");
    let other = AuthAuthorityAnchor::from_root_and_identity(root.path(), b"install-b")
        .expect("应创建另一 authority");

    assert_eq!(first.install_id(), same.install_id());
    assert_eq!(first.directory(), same.directory());
    assert_ne!(first.install_id(), other.install_id());
    assert_eq!(first.install_id().len(), 64);
}

#[test]
fn initialized_directory_without_state_fails_closed() {
    let root = TestRoot::new("missing-state");
    let authority = anchor(&root);
    fs::create_dir_all(authority.directory()).expect("应预建 authority 目录");

    let error = AuthStateStore::open(authority)
        .err()
        .expect("缺失权威状态必须失败");
    assert!(error
        .to_string()
        .contains("missing from an initialized authority directory"));
}

#[test]
fn writer_lock_is_lifetime_exclusive() {
    let root = TestRoot::new("lock");
    let authority = anchor(&root);
    let first = AuthStateStore::open(authority.clone()).expect("首个 writer 应成功");
    let second_error = AuthStateStore::open(authority.clone())
        .err()
        .expect("第二个 writer 必须失败");
    assert!(second_error.to_string().contains("writer"));

    drop(first);
    AuthStateStore::open(authority).expect("释放锁后应能重新打开");
}

#[test]
fn writer_lock_is_exclusive_across_os_processes() {
    let root = TestRoot::new("cross-process-lock");
    let authority = anchor(&root);
    let child = HelperChild::spawn(root.path(), "hold-writer-lock");
    wait_for_path(&root.path().join("helper.ready"), "helper 持锁就绪标记");

    let error = AuthStateStore::open(authority.clone())
        .err()
        .expect("另一 OS 进程持锁时必须拒绝当前 writer");
    assert!(
        error.to_string().contains("writer"),
        "失败原因应明确为 writer lock 竞争"
    );

    fs::write(root.path().join("helper.release"), b"release").expect("应允许 helper 释放锁");
    child.wait_success();
    AuthStateStore::open(authority).expect("helper 正常退出后 OS 应释放 lifetime lock");
}

#[test]
fn crashed_writer_releases_os_lock_and_orphan_temp_never_commits() {
    let root = TestRoot::new("cross-process-crash");
    let authority = anchor(&root);
    let state_path;
    let committed;
    {
        let store = AuthStateStore::open(authority.clone()).expect("应创建 genesis");
        state_path = store.directory().join("state.json");
        committed = fs::read(&state_path).expect("应读取已提交状态");
    }

    let child = HelperChild::spawn(root.path(), "crash-with-orphan-temp");
    wait_for_path(&root.path().join("helper.ready"), "helper 崩溃前就绪标记");
    let orphan = authority.directory().join("state.process-crash.tmp");
    assert!(orphan.exists(), "崩溃前应留下孤立 temp");
    child.terminate();

    let reopened = AuthStateStore::open(authority).expect("崩溃释放 OS 锁后应能重新打开");
    assert_eq!(
        fs::read(&state_path).expect("应再次读取主状态"),
        committed,
        "孤立 temp 绝不能覆盖已提交主状态"
    );
    assert!(!orphan.exists(), "持锁重启应清理孤立 temp");
    assert_eq!(reopened.revision(), 1);
}

#[test]
fn orphan_temp_never_commits_and_is_cleaned() {
    let root = TestRoot::new("orphan-temp");
    let authority = anchor(&root);
    let state_path;
    {
        let store = AuthStateStore::open(authority.clone()).expect("应创建 genesis");
        state_path = store.directory().join("state.json");
    }
    let committed = fs::read(&state_path).expect("应读取已提交状态");
    let orphan = authority.directory().join("state.crash.tmp");
    fs::write(&orphan, b"{\"revision\":999999}").expect("应写入孤立 temp");

    let reopened = AuthStateStore::open(authority).expect("主状态有效时应忽略孤立 temp");
    assert_eq!(fs::read(&state_path).expect("应再次读取主状态"), committed);
    assert!(!orphan.exists());
    assert_eq!(reopened.revision(), 1);
}

#[test]
fn checksum_corruption_requires_explicit_reset() {
    let root = TestRoot::new("corrupt");
    let authority = anchor(&root);
    let state_path;
    {
        let store = AuthStateStore::open(authority.clone()).expect("应创建 genesis");
        state_path = store.directory().join("state.json");
    }
    let json = fs::read_to_string(&state_path).expect("应读取状态");
    let corrupted = json.replacen("\"revision\":1", "\"revision\":2", 1);
    assert_ne!(json, corrupted);
    fs::write(&state_path, corrupted).expect("应写入损坏状态");

    assert!(AuthStateStore::open(authority.clone()).is_err());
    let reset = AuthStateStore::reset_corrupt(authority).expect("显式 reset 应恢复");
    assert_eq!(reset.revision(), 1);
    assert!(!reset.has_session());
}

#[test]
fn stale_attempt_cannot_overwrite_newer_login() {
    let root = TestRoot::new("attempt-cas");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let stale = binding
        .begin_auth_attempt("https://EXAMPLE.com:443/deploy/")
        .expect("应开始首次登录");
    let current = binding
        .begin_auth_attempt("https://example.com/deploy")
        .expect("应开始后续登录");

    assert!(!binding.is_auth_attempt_current(&stale));
    assert!(binding
        .commit_auth_attempt(&stale, "token-a".to_owned(), safe_user(1, "alice"), None)
        .is_err());
    let snapshot = binding
        .commit_auth_attempt(&current, "token-b".to_owned(), safe_user(2, "bob"), None)
        .expect("最新登录应提交");
    assert_eq!(snapshot.session.expect("应有会话").safe_user.name, "bob");
}

#[test]
fn token_rotation_preserves_namespace_cursor_but_invalidates_old_handle() {
    let root = TestRoot::new("rotation");
    let authority = anchor(&root);
    let (old_handle, old_epoch, cursor_key);
    {
        let mut binding = AuthBinding::open(authority.clone()).expect("应打开 binding");
        let attempt = binding
            .begin_auth_attempt("https://example.com/deploy")
            .expect("应开始登录");
        let first = binding
            .commit_auth_attempt(
                &attempt,
                "first-token".to_owned(),
                safe_user(7, "alice"),
                None,
            )
            .expect("应提交登录");
        let session = first.session.expect("应有会话");
        old_epoch = session.session_epoch;
        cursor_key = session.cursor_key;
        old_handle = binding
            .credentialed_request_handle("https://example.com/deploy/api/ab?page=1")
            .expect("应创建请求 handle");
        assert!(binding
            .compare_and_set_cursor(&old_handle, 0, 42, false)
            .expect("cursor CAS 应成功"));

        let next_attempt = binding
            .begin_auth_attempt("https://example.com/deploy")
            .expect("应开始 token 轮换");
        let second = binding
            .commit_auth_attempt(
                &next_attempt,
                "second-token".to_owned(),
                safe_user(7, "alice-renamed"),
                None,
            )
            .expect("应提交 token 轮换");
        let session = second.session.expect("应有新会话");
        assert_eq!(session.cursor_key, cursor_key);
        assert_eq!(session.cursor, 42);
        assert_ne!(session.session_epoch, old_epoch);
        assert!(!binding.is_request_current(&old_handle));
    }

    let reopened = AuthBinding::open(authority).expect("应从磁盘恢复 binding");
    let session = reopened.snapshot().session.expect("重启后应恢复会话");
    assert_eq!(session.cursor, 42);
    assert_eq!(session.cursor_key, cursor_key);
}

#[test]
fn account_switch_uses_separate_namespace_and_relogin_restores_only_its_cursor() {
    let root = TestRoot::new("account-switch");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let first_attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始首次登录");
    let first = binding
        .commit_auth_attempt(
            &first_attempt,
            "alice-token".to_owned(),
            safe_user(1, "alice"),
            None,
        )
        .expect("应提交首次登录");
    let first_session = first.session.expect("应有首次会话");
    let first_handle = binding
        .credentialed_request_handle("https://example.com/api/ab")
        .expect("应创建首次 handle");
    assert!(binding
        .compare_and_set_cursor(&first_handle, 0, 41, false)
        .expect("应保存首次账号 cursor"));

    let second_attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始换账号登录");
    let second = binding
        .commit_auth_attempt(
            &second_attempt,
            "bob-token".to_owned(),
            safe_user(2, "bob"),
            None,
        )
        .expect("应提交换账号登录");
    let second_session = second.session.expect("应有第二个会话");
    assert_ne!(second_session.cursor_key, first_session.cursor_key);
    assert_eq!(second_session.cursor, 0);
    assert!(!binding.is_request_current(&first_handle));

    let return_attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始切回首次账号");
    let returned = binding
        .commit_auth_attempt(
            &return_attempt,
            "alice-rotated-token".to_owned(),
            safe_user(1, "alice"),
            None,
        )
        .expect("应提交切回账号");
    let returned_session = returned.session.expect("应有切回会话");
    assert_eq!(returned_session.cursor_key, first_session.cursor_key);
    assert_eq!(returned_session.cursor, 41);
    assert_eq!(returned_session.capability, AddressBookCapability::Unknown);
    assert!(returned_session.force_full_pending);
    assert!(!returned_session.is_pro);
}

#[test]
fn conditional_clear_rejects_stale_handle_and_never_creates_pending_logout() {
    let root = TestRoot::new("conditional-clear");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let first_attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始首次登录");
    binding
        .commit_auth_attempt(
            &first_attempt,
            "first-token".to_owned(),
            safe_user(1, "alice"),
            None,
        )
        .expect("应提交首次登录");
    let stale_handle = binding
        .credentialed_request_handle("https://example.com/api/currentUser")
        .expect("应创建首次 handle");

    let second_attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始 token 轮换");
    binding
        .commit_auth_attempt(
            &second_attempt,
            "second-token".to_owned(),
            safe_user(1, "alice"),
            None,
        )
        .expect("应提交 token 轮换");
    let current_handle = binding
        .credentialed_request_handle("https://example.com/api/currentUser")
        .expect("应创建当前 handle");

    assert!(!binding
        .clear_auth_session_if_current(&stale_handle)
        .expect("迟到 401 只应返回 false"));
    assert!(binding.snapshot().session.is_some());
    assert!(binding
        .clear_auth_session_if_current(&current_handle)
        .expect("当前 401 应清理会话"));
    let cleared = binding.snapshot();
    assert!(cleared.session.is_none());
    assert_eq!(cleared.pending_logout_count, 0);
}

#[test]
fn changing_api_base_requires_explicit_logout_of_active_session() {
    let root = TestRoot::new("base-switch-fence");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com/deploy")
        .expect("应开始登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "base-a-token".to_owned(),
            safe_user(7, "alice"),
            None,
        )
        .expect("应提交登录");

    assert!(binding
        .begin_auth_attempt("https://other.example.com/deploy")
        .is_err());
    let snapshot = binding.snapshot();
    assert_eq!(
        snapshot
            .session
            .expect("原会话不能被跨 base 登录覆盖")
            .normalized_api_base,
        "https://example.com/deploy"
    );
}

#[test]
fn address_book_completion_updates_cursor_mode_force_full_and_pro_atomically() {
    let root = TestRoot::new("atomic-complete");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "address-book-token".to_owned(),
            safe_user(8, "alice"),
            None,
        )
        .expect("应提交登录");
    let handle = binding
        .credentialed_request_handle("https://example.com/api/ab?page=1&page_size=200")
        .expect("应创建请求 handle");

    let before = binding.snapshot();
    assert!(!binding
        .complete_address_book_pull(&handle, 1, 5, false)
        .expect("错误 expected 应返回 CAS false"));
    assert_eq!(binding.snapshot(), before);

    assert!(binding
        .complete_address_book_pull(&handle, 0, 5, false)
        .expect("地址簿完成提交应成功"));
    let completed = binding.snapshot().session.expect("应保留会话");
    assert_eq!(completed.cursor, 5);
    assert_eq!(
        completed.capability,
        librustdesk::hbbs_http::auth_state_store::AddressBookCapability::Issue9V2
    );
    assert!(!completed.force_full_pending);
    assert!(completed.is_pro);

    assert!(binding
        .complete_address_book_pull(&handle, 5, 1, false)
        .is_err());
    assert_eq!(binding.snapshot().session.expect("应保留会话").cursor, 5);
    assert!(binding
        .complete_address_book_pull(&handle, 5, 1, true)
        .is_err());
    assert!(binding.compare_and_set_cursor(&handle, 5, 1, true).is_err());
    assert!(binding
        .authorize_address_book_reset(&handle, 5, 1)
        .expect("当前 worker 响应应授权 reset"));
    assert!(binding
        .complete_address_book_pull(&handle, 5, 1, true)
        .expect("可信 reset 应允许 cursor 降版"));
    assert_eq!(binding.snapshot().session.expect("应保留会话").cursor, 1);
}

#[test]
fn capability_transition_atomically_marks_completed_legacy_pro_and_preserves_invariants() {
    let root = TestRoot::new("capability-transition");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "capability-token".to_owned(),
            safe_user(9, "alice"),
            None,
        )
        .expect("应提交登录");
    let handle = binding
        .credentialed_request_handle("https://example.com/api/ab")
        .expect("应创建 handle");

    assert!(binding
        .mark_pro_if_current(&handle)
        .expect("应标记本代 PRO"));
    let marked = binding.snapshot();
    assert!(marked.session.as_ref().expect("应有会话").is_pro);
    assert!(!binding
        .mark_pro_if_current(&handle)
        .expect("重复 PRO 标记应为 no-op"));
    assert_eq!(binding.snapshot(), marked);
    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::Legacy, false)
        .expect("应切换 legacy 能力"));
    let legacy = binding.snapshot().session.expect("应有 legacy 会话");
    assert_eq!(legacy.capability, AddressBookCapability::Legacy);
    assert!(!legacy.force_full_pending);
    assert!(legacy.is_pro);
    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::CommercialMulti, true)
        .is_err());
    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::CommercialMulti, false)
        .expect("成功完成 commercial 地址簿应原子标记 PRO"));
    let commercial = binding.snapshot().session.expect("应有 commercial 会话");
    assert_eq!(
        commercial.capability,
        AddressBookCapability::CommercialMulti
    );
    assert!(!commercial.force_full_pending);
    assert!(commercial.is_pro);

    let before = binding.snapshot();
    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::Unknown, false)
        .is_err());
    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::Issue9V2, false)
        .is_err());
    assert_eq!(binding.snapshot(), before);

    assert!(binding
        .set_address_book_capability(&handle, AddressBookCapability::Issue9V2, true)
        .expect("显式激活 v2 应保留 force-full"));
    let activated = binding.snapshot().session.expect("应有 v2 会话");
    assert_eq!(activated.capability, AddressBookCapability::Issue9V2);
    assert!(activated.force_full_pending);
    assert!(!activated.is_pro);
    assert!(!binding
        .complete_address_book_pull(&handle, 1, 2, false)
        .expect("陈旧 ACK 应返回 CAS false"));
    let retryable = binding.snapshot().session.expect("失败 ACK 后应保留会话");
    assert_eq!(retryable.capability, AddressBookCapability::Issue9V2);
    assert!(retryable.force_full_pending);
    assert!(!retryable.is_pro);
}

#[test]
fn stale_or_cross_generation_reset_authorization_cannot_be_reused() {
    let root = TestRoot::new("trusted-reset-cas");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "reset-token-a".to_owned(),
            safe_user(10, "alice"),
            None,
        )
        .expect("应提交登录");
    let handle_a = binding
        .credentialed_request_handle("https://example.com/api/ab")
        .expect("应创建 A 代 handle");
    assert!(binding
        .complete_address_book_pull(&handle_a, 0, 9, false)
        .expect("应先推进 cursor"));
    assert!(binding
        .authorize_address_book_reset(&handle_a, 9, 1)
        .expect("应登记 reset"));

    assert!(binding
        .compare_and_set_cursor(&handle_a, 9, 10, false)
        .expect("并发 ACK 应推进 cursor"));
    assert!(binding
        .complete_address_book_pull(&handle_a, 9, 1, true)
        .is_err());
    assert_eq!(binding.snapshot().session.expect("应保留 A 代").cursor, 10);

    binding
        .begin_logout_current(DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        })
        .expect("应注销 A 代");
    let ticket = binding
        .pending_logout_tickets()
        .pop()
        .expect("应有注销票据");
    binding
        .complete_pending_logout(&ticket)
        .expect("应完成注销");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始 B 代登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "reset-token-b".to_owned(),
            safe_user(10, "alice"),
            None,
        )
        .expect("应提交 B 代");
    let handle_b = binding
        .credentialed_request_handle("https://example.com/api/ab")
        .expect("应创建 B 代 handle");
    assert!(!binding
        .authorize_address_book_reset(&handle_a, 10, 1)
        .expect("旧代 worker 不得授权 reset"));
    assert!(!binding
        .complete_address_book_pull(&handle_a, 10, 1, true)
        .unwrap_or(false));
    assert_eq!(binding.snapshot().session.expect("应保留 B 代").cursor, 10);
    assert!(binding.is_request_current(&handle_b));
}

#[test]
fn logout_is_atomic_fenced_and_uses_identity_snapshot() {
    let root = TestRoot::new("logout");
    let authority = anchor(&root);
    let mut binding = AuthBinding::open(authority.clone()).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始登录");
    binding
        .commit_auth_attempt(
            &attempt,
            "logout-token".to_owned(),
            safe_user(9, "alice"),
            None,
        )
        .expect("应提交登录");
    let handle = binding
        .credentialed_request_handle("https://example.com/api/currentUser")
        .expect("应创建请求 handle");
    let before = binding.snapshot();

    let ticket = binding
        .begin_logout_current(DeviceIdentitySnapshot {
            id: "device-id".to_owned(),
            uuid: "ZGV2aWNlLXV1aWQ=".to_owned(),
        })
        .expect("本地注销应提交")
        .expect("有会话时应创建 pending ticket");
    let ticket_json = serde_json::to_string(&ticket).expect("ticket 应可安全序列化");
    assert!(!ticket_json.contains("logout-token"));
    assert_eq!(binding.pending_logout_tickets(), vec![ticket.clone()]);
    let after = binding.snapshot();
    assert!(after.session.is_none());
    assert_eq!(after.pending_logout_count, 1);
    assert!(after.auth_epoch > before.auth_epoch);
    assert!(after.logout_generation > before.logout_generation);
    assert!(!binding.is_request_current(&handle));
    assert!(binding.begin_auth_attempt("https://example.com").is_err());

    assert!(binding
        .complete_pending_logout(&ticket)
        .expect("应终结 pending logout"));
    assert!(binding.begin_auth_attempt("https://example.com").is_ok());
}

#[test]
fn explicit_logout_without_session_invalidates_inflight_attempt() {
    let root = TestRoot::new("logout-attempt");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    let attempt = binding
        .begin_auth_attempt("https://example.com")
        .expect("应开始登录");
    let generation = binding.snapshot().logout_generation;

    assert!(binding
        .begin_logout_current(DeviceIdentitySnapshot {
            id: String::new(),
            uuid: String::new(),
        })
        .expect("显式注销应提交")
        .is_none());
    assert!(binding.snapshot().logout_generation > generation);
    assert!(!binding.is_auth_attempt_current(&attempt));
    assert!(binding
        .commit_auth_attempt(
            &attempt,
            "late-token".to_owned(),
            safe_user(10, "late"),
            None,
        )
        .is_err());
}

#[test]
fn strict_url_vectors_preserve_base_path_and_reject_cross_origin() {
    assert_eq!(
        normalize_api_base("https://EXAMPLE.com:443/deploy/").expect("应规范化"),
        "https://example.com/deploy"
    );
    assert_eq!(
        normalize_api_base("http://127.0.0.1:21114/").expect("应规范化"),
        "http://127.0.0.1:21114"
    );
    assert!(validate_target_against_base(
        "https://example.com/deploy",
        "https://example.com/deploy/api/ab?page=1"
    )
    .is_ok());
    assert!(validate_target_against_base(
        "https://example.com/deploy",
        "https://example.com/deployment/api/ab"
    )
    .is_err());
    assert!(validate_target_against_base(
        "https://example.com/deploy",
        "https://evil.example/deploy/api/ab"
    )
    .is_err());

    let root = TestRoot::new("remote-http");
    let mut binding = AuthBinding::open(anchor(&root)).expect("应打开 binding");
    assert!(binding.begin_auth_attempt("http://example.com").is_err());
    assert!(binding
        .begin_auth_attempt("http://localhost:21114")
        .is_err());
    assert!(binding.begin_auth_attempt("http://[::1]:21114").is_ok());
}

#[cfg(unix)]
#[test]
fn unix_authority_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("permissions");
    let store = AuthStateStore::open(anchor(&root)).expect("应创建状态");
    let directory_mode = fs::metadata(store.directory())
        .expect("应读取目录权限")
        .permissions()
        .mode()
        & 0o777;
    let state_mode = fs::metadata(store.directory().join("state.json"))
        .expect("应读取文件权限")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(directory_mode, 0o700);
    assert_eq!(state_mode, 0o600);
}
