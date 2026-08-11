use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    rand::{rngs::OsRng, RngCore},
    ResultType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::sync::Mutex;

pub(crate) const NATIVE_AUTH_STATE_SCHEMA: u32 = 1;
pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub(crate) const MAX_PENDING_LOGOUTS: usize = 8;

const AUTH_STATE_FILE: &str = "state.json";
const AUTH_LOCK_FILE: &str = "writer.lock";
const MAX_AUTH_STATE_BYTES: u64 = 4 * 1024 * 1024;
const TEMP_PREFIX: &str = "state.";
const TEMP_SUFFIX: &str = ".tmp";

#[cfg(test)]
static FAIL_NEXT_PERSIST_BEFORE_REPLACE: Mutex<Option<PathBuf>> = Mutex::new(None);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthSafeUser {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub avatar: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub verifier: String,
}

impl std::fmt::Debug for AuthSafeUser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthSafeUser")
            .field("id", &self.id)
            .field("name", &"<redacted>")
            .field("display_name", &"<redacted>")
            .field("avatar", &"<redacted>")
            .field("email", &"<redacted>")
            .field("note", &"<redacted>")
            .field("status", &self.status)
            .field("is_admin", &self.is_admin)
            .field("verifier", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AuthSubject {
    UserId(u64),
    JwtSub(String),
    Username(String),
}

impl AuthSubject {
    pub fn namespace_component(&self) -> String {
        match self {
            Self::UserId(id) => format!("id:{id}"),
            Self::JwtSub(sub) => format!("sub:{sub}"),
            Self::Username(name) => format!("name:{name}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressBookCapability {
    #[default]
    Unknown,
    Issue9V2,
    Legacy,
    CommercialMulti,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthNamespaceState {
    #[serde(default)]
    pub cursor: u64,
    #[serde(default)]
    pub capability: AddressBookCapability,
    #[serde(default)]
    pub force_full_pending: bool,
    #[serde(default)]
    pub pro_epoch: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeAuthSession {
    pub access_token: String,
    pub token_sha256: String,
    pub normalized_api_base: String,
    pub subject: AuthSubject,
    pub cursor_key: String,
    pub epoch: u64,
    pub nonce: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub safe_user: AuthSafeUser,
}

impl std::fmt::Debug for NativeAuthSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthSession")
            .field("access_token", &"<redacted>")
            .field("token_sha256", &self.token_sha256)
            .field("normalized_api_base", &self.normalized_api_base)
            .field("subject", &self.subject)
            .field("cursor_key", &self.cursor_key)
            .field("epoch", &self.epoch)
            .field("nonce", &self.nonce)
            .field("expires_at", &self.expires_at)
            .field("safe_user", &self.safe_user)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthAttemptRecord {
    pub attempt_id: u64,
    pub nonce: String,
    pub normalized_api_base: String,
    pub logout_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthTombstone {
    pub epoch: u64,
    pub nonce: String,
    pub logout_generation: u64,
    #[serde(default)]
    pub normalized_api_base: Option<String>,
    #[serde(default)]
    pub subject_sha256: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingLogout {
    pub ticket_id: String,
    pub normalized_api_base: String,
    pub subject_sha256: String,
    pub logout_generation: u64,
    pub access_token: String,
    #[serde(default)]
    pub token_expires_at: Option<i64>,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_uuid: String,
    #[serde(default)]
    pub attempt_count: u32,
    #[serde(default)]
    pub retry_after_unix_ms: u64,
}

impl std::fmt::Debug for PendingLogout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingLogout")
            .field("ticket_id", &self.ticket_id)
            .field("normalized_api_base", &self.normalized_api_base)
            .field("subject_sha256", &self.subject_sha256)
            .field("logout_generation", &self.logout_generation)
            .field("access_token", &"<redacted>")
            .field("token_expires_at", &self.token_expires_at)
            .field("device_id", &self.device_id)
            .field("device_uuid", &"<redacted>")
            .field("attempt_count", &self.attempt_count)
            .field("retry_after_unix_ms", &self.retry_after_unix_ms)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeAuthStateV1 {
    pub schema: u32,
    pub revision: u64,
    pub auth_epoch: u64,
    pub logout_generation: u64,
    pub attempt_counter: u64,
    #[serde(default)]
    pub latest_attempt: Option<AuthAttemptRecord>,
    #[serde(default)]
    pub session: Option<NativeAuthSession>,
    #[serde(default)]
    pub tombstone: Option<AuthTombstone>,
    #[serde(default)]
    pub pending_logouts: Vec<PendingLogout>,
    #[serde(default)]
    pub namespaces: BTreeMap<String, AuthNamespaceState>,
    pub checksum_sha256: String,
}

impl std::fmt::Debug for NativeAuthStateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthStateV1")
            .field("schema", &self.schema)
            .field("revision", &self.revision)
            .field("auth_epoch", &self.auth_epoch)
            .field("logout_generation", &self.logout_generation)
            .field("attempt_counter", &self.attempt_counter)
            .field("latest_attempt", &self.latest_attempt)
            .field("session_present", &self.session.is_some())
            .field("tombstone", &self.tombstone)
            .field("pending_logout_count", &self.pending_logouts.len())
            .field("namespaces", &self.namespaces)
            .field("checksum_sha256", &self.checksum_sha256)
            .finish()
    }
}

impl NativeAuthStateV1 {
    fn genesis() -> ResultType<Self> {
        let mut state = Self {
            schema: NATIVE_AUTH_STATE_SCHEMA,
            revision: 1,
            auth_epoch: random_safe_seed(),
            logout_generation: random_safe_seed(),
            attempt_counter: 0,
            latest_attempt: None,
            session: None,
            tombstone: None,
            pending_logouts: Vec::new(),
            namespaces: BTreeMap::new(),
            checksum_sha256: String::new(),
        };
        state.refresh_checksum()?;
        Ok(state)
    }

    pub(crate) fn validate(&self) -> ResultType<()> {
        if self.schema != NATIVE_AUTH_STATE_SCHEMA {
            bail!("Unsupported native auth state schema");
        }
        if self.revision == 0 {
            bail!("Native auth state revision is invalid");
        }
        if self.auth_epoch == 0 || self.logout_generation == 0 {
            bail!("Native auth state generation is invalid");
        }
        for (label, value) in [
            ("revision", self.revision),
            ("auth_epoch", self.auth_epoch),
            ("logout_generation", self.logout_generation),
            ("attempt_counter", self.attempt_counter),
        ] {
            if value > MAX_SAFE_INTEGER {
                bail!("Native auth state {label} is outside the safe integer range");
            }
        }
        if self.pending_logouts.len() > MAX_PENDING_LOGOUTS {
            bail!("Native auth pending logout queue exceeds its limit");
        }

        let mut tickets = BTreeSet::new();
        for pending in &self.pending_logouts {
            if pending.ticket_id.is_empty()
                || pending.normalized_api_base.is_empty()
                || !is_lower_hex(&pending.subject_sha256, 64)
                || pending.access_token.is_empty()
                || pending.logout_generation > MAX_SAFE_INTEGER
                || pending.logout_generation > self.logout_generation
                || pending.retry_after_unix_ms > MAX_SAFE_INTEGER
            {
                bail!("Native auth pending logout entry is invalid");
            }
            if !tickets.insert(&pending.ticket_id) {
                bail!("Native auth pending logout ticket is duplicated");
            }
        }

        if let Some(attempt) = &self.latest_attempt {
            if attempt.attempt_id == 0
                || attempt.attempt_id > self.attempt_counter
                || attempt.logout_generation > MAX_SAFE_INTEGER
                || attempt.logout_generation != self.logout_generation
                || !is_lower_hex(&attempt.nonce, 32)
                || attempt.normalized_api_base.is_empty()
            {
                bail!("Native auth attempt metadata is invalid");
            }
        }

        if let Some(session) = &self.session {
            if session.access_token.is_empty()
                || !is_lower_hex(&session.token_sha256, 64)
                || session.normalized_api_base.is_empty()
                || !is_lower_hex(&session.cursor_key, 64)
                || session.epoch > MAX_SAFE_INTEGER
                || session.epoch != self.auth_epoch
                || !is_lower_hex(&session.nonce, 32)
            {
                bail!("Native auth session metadata is invalid");
            }
            if token_sha256(&session.access_token) != session.token_sha256 {
                bail!("Native auth token fingerprint mismatch");
            }
            validate_safe_user(&session.safe_user)?;
            validate_subject(&session.subject)?;
            if cursor_key(&session.normalized_api_base, &session.subject) != session.cursor_key
                || !self.namespaces.contains_key(&session.cursor_key)
            {
                bail!("Native auth session namespace binding is invalid");
            }
            if self.tombstone.is_some() {
                bail!("Native auth state cannot contain a session and tombstone together");
            }
        }

        if let Some(tombstone) = &self.tombstone {
            if tombstone.epoch > MAX_SAFE_INTEGER
                || tombstone.epoch != self.auth_epoch
                || tombstone.logout_generation > MAX_SAFE_INTEGER
                || tombstone.logout_generation != self.logout_generation
                || !is_lower_hex(&tombstone.nonce, 32)
                || tombstone
                    .subject_sha256
                    .as_ref()
                    .is_some_and(|hash| !is_lower_hex(hash, 64))
                || tombstone.normalized_api_base.is_some() != tombstone.subject_sha256.is_some()
            {
                bail!("Native auth tombstone is invalid");
            }
        }

        for (key, namespace) in &self.namespaces {
            if !is_lower_hex(key, 64)
                || namespace.cursor > MAX_SAFE_INTEGER
                || namespace
                    .pro_epoch
                    .is_some_and(|epoch| epoch > MAX_SAFE_INTEGER)
            {
                bail!("Native auth namespace state is invalid");
            }
        }

        if !is_lower_hex(&self.checksum_sha256, 64) {
            bail!("Native auth state checksum encoding is invalid");
        }
        let expected = self.compute_checksum()?;
        if !constant_time_eq(expected.as_bytes(), self.checksum_sha256.as_bytes()) {
            bail!("Native auth state checksum mismatch");
        }
        Ok(())
    }

    fn refresh_checksum(&mut self) -> ResultType<()> {
        self.checksum_sha256.clear();
        self.checksum_sha256 = self.compute_checksum()?;
        Ok(())
    }

    fn compute_checksum(&self) -> ResultType<String> {
        let mut canonical = self.clone();
        canonical.checksum_sha256.clear();
        let bytes = serde_json::to_vec(&canonical)
            .context("Failed to serialize native auth state for checksum")?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthAuthorityAnchor {
    root: PathBuf,
    install_id: String,
}

impl AuthAuthorityAnchor {
    pub fn for_current_install() -> ResultType<Self> {
        let root = hbb_common::config::Config::get_home()
            .join(".rustdesk")
            .join("ui_auth_v1");
        let executable = std::env::current_exe()
            .context("Failed to resolve current executable for auth authority")?;
        let canonical = match fs::canonicalize(&executable) {
            Ok(path) => path,
            Err(_) => executable,
        };
        let install_dir = match canonical.parent() {
            Some(parent) => parent.to_path_buf(),
            None => canonical,
        };
        let identity = install_dir.to_string_lossy();
        Self::from_root_and_identity(root, identity.as_bytes())
    }

    pub fn from_root_and_identity(
        root: impl Into<PathBuf>,
        install_identity: impl AsRef<[u8]>,
    ) -> ResultType<Self> {
        let identity = install_identity.as_ref();
        if identity.is_empty() {
            bail!("Auth authority install identity must not be empty");
        }
        let install_id = sha256_hex(
            [b"rustdesk-ui-auth-authority-v1\0".as_slice(), identity]
                .concat()
                .as_slice(),
        );
        Ok(Self {
            root: root.into(),
            install_id,
        })
    }

    pub fn directory(&self) -> PathBuf {
        self.root.join(&self.install_id)
    }

    pub fn install_id(&self) -> &str {
        &self.install_id
    }
}

pub struct AuthStateStore {
    directory: PathBuf,
    state_path: PathBuf,
    lock: AuthWriterLock,
    state: NativeAuthStateV1,
}

impl AuthStateStore {
    pub fn open(anchor: AuthAuthorityAnchor) -> ResultType<Self> {
        let directory = anchor.directory();
        let directory_existed = directory.exists();
        create_private_directory(&directory)?;
        let lock = AuthWriterLock::acquire(&directory.join(AUTH_LOCK_FILE))?;
        let state_path = directory.join(AUTH_STATE_FILE);
        let temp_trace_exists = has_temp_trace(&directory)?;
        cleanup_temp_files(&directory)?;

        let state = if state_path.exists() {
            set_private_file_permissions(&state_path)?;
            read_state(&state_path)?
        } else if directory_existed || temp_trace_exists {
            bail!("Native auth state is missing from an initialized authority directory");
        } else {
            let state = NativeAuthStateV1::genesis()?;
            persist_state(&directory, &state_path, &state, false)?;
            state
        };

        Ok(Self {
            directory,
            state_path,
            lock,
            state,
        })
    }

    pub fn reset_corrupt(anchor: AuthAuthorityAnchor) -> ResultType<Self> {
        let directory = anchor.directory();
        create_private_directory(&directory)?;
        let lock = AuthWriterLock::acquire(&directory.join(AUTH_LOCK_FILE))?;
        let state_path = directory.join(AUTH_STATE_FILE);
        cleanup_temp_files(&directory)?;
        if state_path.exists() {
            set_private_file_permissions(&state_path)?;
            let quarantine = directory.join(format!(
                "state.corrupt.{}.json",
                hbb_common::uuid::Uuid::new_v4()
            ));
            fs::rename(&state_path, quarantine)
                .context("Failed to quarantine corrupt native auth state")?;
        }
        let state = NativeAuthStateV1::genesis()?;
        persist_state(&directory, &state_path, &state, false)?;
        Ok(Self {
            directory,
            state_path,
            lock,
            state,
        })
    }

    pub(crate) fn snapshot(&self) -> NativeAuthStateV1 {
        self.state.clone()
    }

    pub fn revision(&self) -> u64 {
        self.state.revision
    }

    pub fn has_session(&self) -> bool {
        self.state.session.is_some()
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn update<F>(&mut self, mutate: F) -> ResultType<NativeAuthStateV1>
    where
        F: FnOnce(&mut NativeAuthStateV1) -> ResultType<()>,
    {
        let disk_state = read_state(&self.state_path)?;
        if disk_state.revision != self.state.revision
            || disk_state.checksum_sha256 != self.state.checksum_sha256
        {
            bail!("Native auth state changed outside the active writer");
        }

        let previous_revision = disk_state.revision;
        let previous_auth_epoch = disk_state.auth_epoch;
        let previous_logout_generation = disk_state.logout_generation;
        let previous_attempt_counter = disk_state.attempt_counter;
        let mut next = disk_state;
        mutate(&mut next)?;
        if next.schema != NATIVE_AUTH_STATE_SCHEMA
            || next.revision != previous_revision
            || next.auth_epoch < previous_auth_epoch
            || next.logout_generation < previous_logout_generation
            || next.attempt_counter < previous_attempt_counter
        {
            bail!("Native auth mutation attempted to weaken monotonic state");
        }
        next.revision = checked_increment(previous_revision, "revision")?;
        next.refresh_checksum()?;
        next.validate()?;
        persist_state(&self.directory, &self.state_path, &next, true)?;
        self.state = next.clone();
        Ok(next)
    }
}

impl Drop for AuthStateStore {
    fn drop(&mut self) {
        let _ = &self.lock;
    }
}

pub(crate) fn checked_increment(value: u64, label: &str) -> ResultType<u64> {
    value
        .checked_add(1)
        .filter(|next| *next <= MAX_SAFE_INTEGER)
        .ok_or_else(|| anyhow!("Native auth {label} exhausted its safe integer range"))
}

pub(crate) fn token_sha256(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub(crate) fn subject_sha256(subject: &AuthSubject) -> String {
    sha256_hex(subject.namespace_component().as_bytes())
}

pub(crate) fn cursor_key(normalized_api_base: &str, subject: &AuthSubject) -> String {
    sha256_hex(format!("{}\n{}", normalized_api_base, subject.namespace_component()).as_bytes())
}

pub(crate) fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_safe_seed() -> u64 {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    (u64::from_le_bytes(bytes) % MAX_SAFE_INTEGER) + 1
}

fn validate_safe_user(user: &AuthSafeUser) -> ResultType<()> {
    if user.name.is_empty() || user.name.chars().any(char::is_control) {
        bail!("Native auth safe user has an invalid name");
    }
    if user.id.is_some_and(|id| id == 0 || id > MAX_SAFE_INTEGER) {
        bail!("Native auth safe user id is invalid");
    }
    Ok(())
}

fn read_state(path: &Path) -> ResultType<NativeAuthStateV1> {
    let mut file = File::open(path).context("Failed to open native auth state")?;
    let length = file
        .metadata()
        .context("Failed to inspect native auth state")?
        .len();
    if length == 0 || length > MAX_AUTH_STATE_BYTES {
        bail!("Native auth state size is invalid");
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)
        .context("Failed to read native auth state")?;
    let state: NativeAuthStateV1 =
        serde_json::from_slice(&bytes).context("Failed to parse native auth state")?;
    state.validate()?;
    Ok(state)
}

fn persist_state(
    directory: &Path,
    state_path: &Path,
    state: &NativeAuthStateV1,
    replace_existing: bool,
) -> ResultType<()> {
    let bytes = serde_json::to_vec(state).context("Failed to serialize native auth state")?;
    if bytes.len() as u64 > MAX_AUTH_STATE_BYTES {
        bail!("Native auth state exceeds its size limit");
    }

    let temp_path = directory.join(format!(
        "{TEMP_PREFIX}{}{TEMP_SUFFIX}",
        hbb_common::uuid::Uuid::new_v4()
    ));
    let write_result = (|| -> ResultType<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true).read(true);
        let mut temp = options
            .open(&temp_path)
            .context("Failed to create native auth temporary state")?;
        set_private_file_permissions(&temp_path)?;
        temp.write_all(&bytes)
            .context("Failed to write native auth temporary state")?;
        temp.sync_all()
            .context("Failed to sync native auth temporary state")?;
        drop(temp);
        #[cfg(test)]
        {
            let mut injected_directory = FAIL_NEXT_PERSIST_BEFORE_REPLACE
                .lock()
                .expect("持久化故障注入锁不应中毒");
            if injected_directory.as_deref() == Some(directory) {
                *injected_directory = None;
                bail!("Injected native auth persistence failure before replace");
            }
        }
        atomic_replace(
            &temp_path,
            state_path,
            replace_existing && state_path.exists(),
        )?;
        sync_directory(directory)?;
        Ok(())
    })();
    if write_result.is_err() && temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

#[cfg(test)]
pub(crate) fn fail_next_persist_before_replace(directory: &Path) {
    *FAIL_NEXT_PERSIST_BEFORE_REPLACE
        .lock()
        .expect("持久化故障注入锁不应中毒") = Some(directory.to_path_buf());
}

fn create_private_directory(path: &Path) -> ResultType<()> {
    fs::create_dir_all(path).context("Failed to create native auth authority directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("Failed to secure native auth authority directory")?;
    }
    #[cfg(windows)]
    set_private_windows_acl(path, true)?;
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> ResultType<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("Failed to secure native auth state file")?;
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        set_private_windows_acl(path, false)?;
        #[cfg(not(windows))]
        let _ = path;
    }
    Ok(())
}

#[cfg(windows)]
fn set_private_windows_acl(path: &Path, is_directory: bool) -> ResultType<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR,
            },
        },
    };

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let descriptor_text = if is_directory {
        "D:P(A;OICI;FA;;;OW)"
    } else {
        "D:P(A;;FA;;;OW)"
    };
    let descriptor_wide: Vec<u16> = descriptor_text
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(descriptor_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .context("Failed to build private native auth security descriptor")?;
    }
    let result = unsafe {
        SetFileSecurityW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok()
        .context("Failed to apply private native auth ACL")
    };
    if !descriptor.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
    }
    result
}

fn has_temp_trace(directory: &Path) -> ResultType<bool> {
    for entry in fs::read_dir(directory).context("Failed to inspect native auth directory")? {
        let entry = entry.context("Failed to inspect native auth directory entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cleanup_temp_files(directory: &Path) -> ResultType<()> {
    for entry in fs::read_dir(directory).context("Failed to inspect native auth directory")? {
        let entry = entry.context("Failed to inspect native auth directory entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
            fs::remove_file(entry.path())
                .context("Failed to remove native auth temporary state")?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(temp_path: &Path, state_path: &Path, _replace_existing: bool) -> ResultType<()> {
    fs::rename(temp_path, state_path).context("Failed to atomically replace native auth state")
}

#[cfg(windows)]
fn atomic_replace(temp_path: &Path, state_path: &Path, replace_existing: bool) -> ResultType<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{
            MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
        },
    };

    let temp_wide: Vec<u16> = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let state_wide: Vec<u16> = state_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        if replace_existing {
            ReplaceFileW(
                PCWSTR::from_raw(state_wide.as_ptr()),
                PCWSTR::from_raw(temp_wide.as_ptr()),
                PCWSTR::null(),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
            .context("Failed to replace native auth state")?;
        } else {
            MoveFileExW(
                PCWSTR::from_raw(temp_wide.as_ptr()),
                PCWSTR::from_raw(state_wide.as_ptr()),
                MOVEFILE_WRITE_THROUGH,
            )
            .context("Failed to publish native auth state")?;
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_replace(temp_path: &Path, state_path: &Path, _replace_existing: bool) -> ResultType<()> {
    fs::rename(temp_path, state_path).context("Failed to atomically replace native auth state")
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> ResultType<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .context("Failed to sync native auth authority directory")
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> ResultType<()> {
    Ok(())
}

struct AuthWriterLock {
    file: File,
}

impl AuthWriterLock {
    fn acquire(path: &Path) -> ResultType<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .context("Failed to open native auth writer lock")?;
        set_private_file_permissions(path)?;

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe {
                hbb_common::libc::flock(
                    file.as_raw_fd(),
                    hbb_common::libc::LOCK_EX | hbb_common::libc::LOCK_NB,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("Another native auth writer is already active");
            }
            Ok(Self { file })
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::{
                Foundation::HANDLE,
                Storage::FileSystem::{
                    LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
                },
                System::IO::OVERLAPPED,
            };
            let mut overlapped = OVERLAPPED::default();
            let handle = HANDLE(file.as_raw_handle());
            unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    None,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
                .context("Another native auth writer is already active")?;
            }
            Ok(Self { file })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self { file })
        }
    }
}

impl Drop for AuthWriterLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe {
                hbb_common::libc::flock(self.file.as_raw_fd(), hbb_common::libc::LOCK_UN)
            };
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::{
                Foundation::HANDLE, Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED,
            };
            let handle = HANDLE(self.file.as_raw_handle());
            let mut overlapped = OVERLAPPED::default();
            let _ = unsafe { UnlockFileEx(handle, None, u32::MAX, u32::MAX, &mut overlapped) };
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_subject(subject: &AuthSubject) -> ResultType<()> {
    match subject {
        AuthSubject::UserId(id) if *id == 0 || *id > MAX_SAFE_INTEGER => {
            bail!("Native auth subject user id is invalid")
        }
        AuthSubject::JwtSub(subject) | AuthSubject::Username(subject)
            if subject.is_empty() || subject.chars().any(char::is_control) =>
        {
            bail!("Native auth subject text is invalid")
        }
        _ => Ok(()),
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}
