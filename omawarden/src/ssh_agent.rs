//! OpenSSH agent backed by the vault's SSH key items.
//!
//! The daemon listens on `$XDG_RUNTIME_DIR/omawarden-ssh-agent.sock` when
//! `ssh_agent_enabled` is set. Private keys are parsed only for the duration
//! of a single signature. Signing asks for confirmation in the Omarchy overlay
//! according to `ssh_agent_confirm`:
//!
//! - `always`: every signature
//! - `first-use` (default): once per key and client program, until the vault locks
//! - `never`: no prompt (the vault still has to be unlocked)
//!
//! Requests that arrive through agent forwarding (OpenSSH's
//! `session-bind@openssh.com` with `is_forwarding`) are always confirmed,
//! whatever the policy, so a remote host can't use your keys silently.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::Digest;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

use crate::daemon::DaemonState;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;

const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// Largest agent message accepted (OpenSSH uses 256 KiB as well).
const MAX_MESSAGE: usize = 256 * 1024;
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(60);

pub fn socket_path() -> PathBuf {
    crate::daemon::get_runtime_dir().join("omawarden-ssh-agent.sock")
}

// ---------------------------------------------------------------------------
// Confirmation prompts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Always,
    FirstUse,
    Never,
}

impl Confirm {
    pub fn parse(s: &str) -> Confirm {
        match s {
            "always" => Confirm::Always,
            "never" => Confirm::Never,
            _ => Confirm::FirstUse,
        }
    }
}

/// What the overlay shows for a pending signature.
#[derive(Debug, Clone, Serialize)]
pub struct Prompt {
    pub id: u64,
    /// Short question, e.g. "Sign a Git commit?".
    pub title: String,
    /// What is being signed, e.g. "SSH login as git@github.com".
    pub action: String,
    pub key_name: String,
    pub fingerprint: String,
    /// Requesting program, e.g. "git (ssh)".
    pub client: String,
    pub command: String,
    pub forwarded: bool,
    /// Whether "Allow until lock" applies (first-use policy, not forwarded).
    pub can_remember: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Decision {
    pub approve: bool,
    pub remember: bool,
}

struct Pending {
    prompt: Prompt,
    decision: Option<Decision>,
}

pub struct SshAgent {
    pending: Mutex<HashMap<u64, Pending>>,
    answered: Condvar,
    next_id: AtomicU64,
    /// Approved "fingerprint|client exe" pairs, valid for one unlock session.
    approvals: Mutex<(Option<Instant>, HashSet<String>)>,
    /// Whether the socket is currently bound.
    running: std::sync::atomic::AtomicBool,
}

impl Default for SshAgent {
    fn default() -> Self {
        SshAgent {
            pending: Mutex::new(HashMap::new()),
            answered: Condvar::new(),
            next_id: AtomicU64::new(1),
            approvals: Mutex::new((None, HashSet::new())),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl SshAgent {
    /// Pending prompts, oldest first (for the overlay).
    pub fn pending(&self) -> Vec<Prompt> {
        let mut list: Vec<Prompt> = self
            .pending
            .lock()
            .map(|p| {
                p.values()
                    .filter(|p| p.decision.is_none())
                    .map(|p| p.prompt.clone())
                    .collect()
            })
            .unwrap_or_default();
        list.sort_by_key(|p| p.id);
        list
    }

    /// Answer a prompt. Returns false if it no longer exists.
    pub fn reply(&self, id: u64, decision: Decision) -> bool {
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        match pending.get_mut(&id) {
            Some(p) if p.decision.is_none() => {
                p.decision = Some(decision);
                self.answered.notify_all();
                true
            }
            _ => false,
        }
    }

    fn ask(&self, mut prompt: Prompt) -> Decision {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        prompt.id = id;
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(
                id,
                Pending {
                    prompt,
                    decision: None,
                },
            );
        }
        summon_overlay(&serde_json::json!({ "view": "ssh-approval", "id": id }));

        let deadline = Instant::now() + PROMPT_TIMEOUT;
        let Ok(mut pending) = self.pending.lock() else {
            return Decision::default();
        };
        let decision = loop {
            if let Some(d) = pending.get(&id).and_then(|p| p.decision) {
                break d;
            }
            let now = Instant::now();
            if now >= deadline {
                break Decision::default();
            }
            match self.answered.wait_timeout(pending, deadline - now) {
                Ok((guard, _)) => pending = guard,
                Err(_) => return Decision::default(),
            }
        };
        pending.remove(&id);
        decision
    }

    fn is_approved(&self, session: Option<Instant>, key: &str) -> bool {
        let Ok(mut a) = self.approvals.lock() else {
            return false;
        };
        if a.0 != session {
            // The vault was locked (or re-unlocked) since: start over.
            *a = (session, HashSet::new());
        }
        a.1.contains(key)
    }

    fn approve(&self, session: Option<Instant>, key: String) {
        if let Ok(mut a) = self.approvals.lock() {
            if a.0 != session {
                *a = (session, HashSet::new());
            }
            a.1.insert(key);
        }
    }
}

/// Open the Omarchy Bitwarden overlay (for a prompt, or to unlock).
fn summon_overlay(payload: &serde_json::Value) {
    let Some(shell) = crate::daemon::get_omarchy_shell_cmd() else {
        crate::log_warn!(
            "omawarden:ssh-agent",
            "omarchy-shell not found; cannot show the confirmation prompt"
        );
        return;
    };
    let result = std::process::Command::new(shell)
        .args(["shell", "summon", "icyleaf.bitwarden", &payload.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match result {
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => crate::log_warn!("omawarden:ssh-agent", "could not summon the overlay: {}", e),
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Start or stop the agent to match the `ssh_agent_enabled` setting, without
/// restarting the daemon (which would lock the vault).
pub fn apply(state: &Arc<DaemonState>) -> std::io::Result<bool> {
    let enabled = crate::config::ConfigManager::default()
        .load()
        .ssh_agent_enabled;
    let running = state.ssh_agent.running.load(Ordering::SeqCst);
    if enabled && !running {
        spawn(state.clone())?;
    } else if !enabled && running {
        // An unlinked socket can't be connected to; the idle accept thread
        // ends with the daemon.
        state.ssh_agent.running.store(false, Ordering::SeqCst);
        remove_socket();
        crate::log_info!("omawarden:ssh-agent", "stopped");
    }
    Ok(enabled)
}

pub fn is_running(state: &DaemonState) -> bool {
    state.ssh_agent.running.load(Ordering::SeqCst)
}

/// Bind the agent socket and serve it on background threads.
pub fn spawn(state: Arc<DaemonState>) -> std::io::Result<()> {
    let path = socket_path();
    if path.exists() {
        crate::daemon::validate_socket_path(&path)?;
        let _ = fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    crate::log_info!("omawarden:ssh-agent", "listening on {}", path.display());
    state.ssh_agent.running.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if !state.ssh_agent.running.load(Ordering::SeqCst) {
                break;
            }
            match stream {
                Ok(stream) => {
                    let st = state.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = serve(&st, stream) {
                            crate::log_debug!("omawarden:ssh-agent", "client ended: {}", e);
                        }
                    });
                }
                Err(e) => crate::log_warn!("omawarden:ssh-agent", "accept failed: {}", e),
            }
        }
    });
    Ok(())
}

pub fn remove_socket() {
    let _ = fs::remove_file(socket_path());
}

/// Per-connection context.
struct Conn {
    peer: Peer,
    /// Destination host learned from session-bind, if known.
    host: Option<String>,
    forwarded: bool,
}

fn serve(state: &Arc<DaemonState>, mut stream: UnixStream) -> std::io::Result<()> {
    crate::daemon::verify_peer_credentials(&stream)?;
    let mut conn = Conn {
        peer: Peer::of(&stream),
        host: None,
        forwarded: false,
    };
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(std::io::Error::other("bad message length"));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;
        let (kind, body) = (msg[0], &msg[1..]);
        match kind {
            REQUEST_IDENTITIES => send(&mut stream, IDENTITIES_ANSWER, &identities(state, &conn))?,
            SIGN_REQUEST => match sign(state, &conn, body) {
                Ok(sig) => {
                    let mut out = Vec::new();
                    put_string(&mut out, &sig);
                    send(&mut stream, SIGN_RESPONSE, &out)?;
                }
                Err(e) => {
                    crate::log_info!("omawarden:ssh-agent", "signature refused: {}", e);
                    send(&mut stream, FAILURE, &[])?;
                }
            },
            EXTENSION => {
                let mut r = Reader(body);
                let reply = match (r.string().ok(), r.0) {
                    (Some(b"session-bind@openssh.com"), rest) => match parse_session_bind(rest) {
                        Some((hostkey, forwarded)) => {
                            conn.host = known_host_for(&hostkey);
                            // Sticky: a forwarded chain binds once per hop.
                            conn.forwarded |= forwarded;
                            SUCCESS
                        }
                        None => FAILURE,
                    },
                    _ => EXTENSION_FAILURE,
                };
                send(&mut stream, reply, &[])?;
            }
            // Adding/removing keys and locking the agent are managed by the vault.
            _ => send(&mut stream, FAILURE, &[])?,
        }
    }
}

fn send(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

// ---------------------------------------------------------------------------
// Vault keys
// ---------------------------------------------------------------------------

struct AgentKey {
    name: String,
    blob: Vec<u8>,
    fingerprint: String,
    private_key: Zeroizing<String>,
    passphrase: Option<Zeroizing<String>>,
}

fn blob_of(public_key: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(public_key.split_whitespace().nth(1)?)
        .ok()
}

fn vault_keys(state: &DaemonState) -> Vec<AgentKey> {
    state
        .vault_mgr
        .get_items()
        .into_iter()
        .filter_map(|item| {
            let ssh = item.ssh_key?;
            let private_key = Zeroizing::new(ssh.private_key?);
            // Derive the public key when the item doesn't store one.
            let public = match ssh.public_key {
                Some(p) if !p.trim().is_empty() => p,
                _ => PrivateKey::from_openssh(private_key.as_bytes())
                    .ok()?
                    .public_key()
                    .to_openssh()
                    .ok()?,
            };
            let blob = blob_of(&public)?;
            let fingerprint = ssh
                .fingerprint
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| {
                    ssh_key::PublicKey::from_openssh(&public)
                        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
                        .unwrap_or_default()
                });
            Some(AgentKey {
                name: item.name,
                blob,
                fingerprint,
                private_key,
                passphrase: ssh.passphrase.map(Zeroizing::new),
            })
        })
        .collect()
}

/// Wait for the vault to be unlocked, opening the overlay so the person can.
fn wait_for_unlock(state: &DaemonState) -> bool {
    if state.vault_mgr.is_unlocked() {
        return true;
    }
    summon_overlay(&serde_json::json!({}));
    let deadline = Instant::now() + UNLOCK_TIMEOUT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if state.vault_mgr.is_unlocked() {
            return true;
        }
    }
    false
}

fn identities(state: &DaemonState, _conn: &Conn) -> Vec<u8> {
    let keys = if wait_for_unlock(state) {
        vault_keys(state)
    } else {
        Vec::new()
    };
    let mut out = (keys.len() as u32).to_be_bytes().to_vec();
    for k in &keys {
        put_string(&mut out, &k.blob);
        put_string(&mut out, k.name.as_bytes());
    }
    out
}

fn sign(state: &DaemonState, conn: &Conn, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader(body);
    let key_blob = r.string()?.to_vec();
    let data = r.string()?.to_vec();
    let flags = r.u32().unwrap_or(0);

    if !wait_for_unlock(state) {
        return Err("vault is locked".into());
    }
    let key = vault_keys(state)
        .into_iter()
        .find(|k| k.blob == key_blob)
        .ok_or("key not in vault")?;

    let cfg = crate::config::ConfigManager::default().load();
    let policy = Confirm::parse(&cfg.ssh_agent_confirm);
    let session = state.unlocked_at.lock().ok().and_then(|g| *g);
    let remember_key = format!("{}|{}", key.fingerprint, conn.peer.exe);
    let needs_prompt = conn.forwarded
        || match policy {
            Confirm::Never => false,
            Confirm::Always => true,
            Confirm::FirstUse => !state.ssh_agent.is_approved(session, &remember_key),
        };
    if needs_prompt {
        let (title, action) = describe(&purpose(&data), conn.host.as_deref());
        let decision = state.ssh_agent.ask(Prompt {
            id: 0,
            title,
            action,
            key_name: key.name.clone(),
            fingerprint: key.fingerprint.clone(),
            client: conn.peer.describe(),
            command: conn.peer.cmdline.clone(),
            forwarded: conn.forwarded,
            can_remember: policy == Confirm::FirstUse && !conn.forwarded,
        });
        if !decision.approve {
            return Err("denied".into());
        }
        if policy == Confirm::FirstUse && !conn.forwarded {
            state.ssh_agent.approve(session, remember_key);
        }
    }

    let mut private = PrivateKey::from_openssh(key.private_key.as_bytes())
        .map_err(|e| format!("parsing private key: {e}"))?;
    if private.is_encrypted() {
        let pass = key
            .passphrase
            .as_ref()
            .ok_or("key is encrypted and the item has no passphrase")?;
        private = private
            .decrypt(pass.as_bytes())
            .map_err(|e| format!("decrypting private key: {e}"))?;
    }
    sign_with(&private, &data, flags)
}

/// Produce an SSH signature blob (string algorithm, string signature).
pub fn sign_with(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    use ssh_encoding::Encode;
    use ssh_key::Signature;
    let signature = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(kp) => {
            let rsa_key = rsa_private_key(kp)?;
            let (hash, sig) = if flags & RSA_SHA2_512 != 0 {
                (
                    Some(HashAlg::Sha512),
                    rsa_key.sign(
                        rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        &sha2::Sha512::digest(data),
                    ),
                )
            } else if flags & RSA_SHA2_256 != 0 {
                (
                    Some(HashAlg::Sha256),
                    rsa_key.sign(
                        rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &sha2::Sha256::digest(data),
                    ),
                )
            } else {
                (
                    None,
                    rsa_key.sign(
                        rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                        &sha1::Sha1::digest(data),
                    ),
                )
            };
            let sig = sig.map_err(|e| format!("rsa sign: {e}"))?;
            Signature::new(Algorithm::Rsa { hash }, sig).map_err(|e| e.to_string())?
        }
        _ => signature::Signer::try_sign(key, data).map_err(|e| format!("sign: {e}"))?,
    };
    let mut out = Vec::new();
    signature
        .encode(&mut out)
        .map_err(|e| format!("encode: {e}"))?;
    Ok(out)
}

/// ssh-key's own RsaKeypair → rsa conversion rejects valid keys; build it
/// from the raw components instead.
fn rsa_private_key(kp: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    use rsa::BigUint;
    let int = |m: &ssh_key::Mpint| -> Result<BigUint, String> {
        Ok(BigUint::from_bytes_be(
            m.as_positive_bytes().ok_or("negative RSA component")?,
        ))
    };
    rsa::RsaPrivateKey::from_components(
        int(&kp.public.n)?,
        int(&kp.public.e)?,
        int(&kp.private.d)?,
        vec![int(&kp.private.p)?, int(&kp.private.q)?],
    )
    .map_err(|e| format!("rsa key: {e}"))
}

// ---------------------------------------------------------------------------
// Describing a request
// ---------------------------------------------------------------------------

/// What a signature is for, decoded from the data being signed.
#[derive(Debug, PartialEq)]
pub enum Purpose {
    /// SSH user authentication (RFC 4252): logging in as `user`.
    Login {
        user: String,
    },
    /// `ssh-keygen -Y sign` (SSHSIG); namespace "git" is a commit/tag signature.
    Sig {
        namespace: String,
    },
    Unknown,
}

pub fn purpose(data: &[u8]) -> Purpose {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        return match Reader(rest).string() {
            Ok(ns) => Purpose::Sig {
                namespace: String::from_utf8_lossy(ns).into_owned(),
            },
            Err(_) => Purpose::Unknown,
        };
    }
    let mut r = Reader(data);
    let parsed = (|| -> Result<Purpose, String> {
        let _session_id = r.string()?;
        if r.byte()? != 50 {
            return Err("not a userauth request".into());
        }
        let user = String::from_utf8_lossy(r.string()?).into_owned();
        let service = r.string()?;
        let method = r.string()?;
        if service != b"ssh-connection" || method != b"publickey" {
            return Err("unexpected service".into());
        }
        Ok(Purpose::Login { user })
    })();
    parsed.unwrap_or(Purpose::Unknown)
}

fn describe(purpose: &Purpose, host: Option<&str>) -> (String, String) {
    match purpose {
        Purpose::Login { user } => match host {
            Some(h) => (
                format!("Log in to {h}?"),
                format!("SSH login as {user}@{h}"),
            ),
            None => ("Log in with SSH?".into(), format!("SSH login as {user}")),
        },
        Purpose::Sig { namespace } if namespace == "git" => (
            "Sign with Git?".into(),
            "Git commit or tag signature".into(),
        ),
        Purpose::Sig { namespace } if namespace == "file" => {
            ("Sign a file?".into(), "File signature".into())
        }
        Purpose::Sig { namespace } => ("Sign data?".into(), format!("Signature ({namespace})")),
        Purpose::Unknown => ("Use SSH key?".into(), "Unrecognized signing request".into()),
    }
}

/// `session-bind@openssh.com` body: string hostkey, string session id,
/// string signature, bool is_forwarding. Returns (hostkey, is_forwarding).
fn parse_session_bind(body: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut r = Reader(body);
    let hostkey = r.string().ok()?.to_vec();
    r.string().ok()?;
    r.string().ok()?;
    let forwarded = r.byte().ok()? != 0;
    Some((hostkey, forwarded))
}

/// Map a server host key to a host name via ~/.ssh/known_hosts (plain
/// entries only; hashed entries can't be reversed).
fn known_host_for(hostkey: &[u8]) -> Option<String> {
    use base64::Engine;
    let path = Path::new(&std::env::var("HOME").ok()?).join(".ssh/known_hosts");
    let text = fs::read_to_string(path).ok()?;
    let wanted = base64::engine::general_purpose::STANDARD.encode(hostkey);
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let mut hosts = fields.next()?;
        if hosts.starts_with('@') {
            hosts = fields.next()?;
        }
        let (_kind, key) = (fields.next()?, fields.next()?);
        if key != wanted || hosts.starts_with('|') {
            return None;
        }
        let first = hosts.split(',').next()?;
        Some(
            first
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(first)
                .to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Peer process
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Peer {
    pid: i32,
    exe: String,
    comm: String,
    cmdline: String,
}

impl Peer {
    fn of(stream: &UnixStream) -> Peer {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } == 0;
        if ok {
            Peer::from_pid(cred.pid)
        } else {
            Peer::default()
        }
    }

    fn from_pid(pid: i32) -> Peer {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let exe = fs::read_link(proc.join("exe"))
            .map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .unwrap_or_default();
        let comm = fs::read_to_string(proc.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline = fs::read(proc.join("cmdline"))
            .map(|b| {
                b.split(|c| *c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        Peer {
            pid,
            exe,
            comm,
            cmdline,
        }
    }

    fn parent(&self) -> Option<Peer> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
        // Fields after the parenthesised comm (which may contain spaces).
        let ppid: i32 = stat
            .rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        (ppid > 1).then(|| Peer::from_pid(ppid))
    }

    /// "git (ssh)", "ssh", "ssh-keygen"…
    fn describe(&self) -> String {
        let mut who = if self.comm.is_empty() {
            "A program".to_string()
        } else {
            self.comm.clone()
        };
        if self.comm == "ssh" {
            if let Some(parent) = self.parent() {
                if !parent.comm.is_empty()
                    && !matches!(parent.comm.as_str(), "bash" | "zsh" | "fish" | "sh" | "nu")
                {
                    who = format!("{} (ssh)", parent.comm);
                }
            }
        }
        who
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let (b, rest) = self.0.split_first().ok_or("short read")?;
        self.0 = rest;
        Ok(*b)
    }
    fn u32(&mut self) -> Result<u32, String> {
        if self.0.len() < 4 {
            return Err("short read".into());
        }
        let (n, rest) = self.0.split_at(4);
        self.0 = rest;
        Ok(u32::from_be_bytes([n[0], n[1], n[2], n[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            return Err("short string".into());
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(s)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use ssh_key::LineEnding;

    fn verify(key: &PrivateKey, data: &[u8], blob: &[u8]) -> ssh_key::Signature {
        let sig = <ssh_key::Signature as ssh_encoding::Decode>::decode(&mut &blob[..]).unwrap();
        signature::Verifier::verify(key.public_key(), data, &sig).unwrap();
        sig
    }

    #[test]
    fn ed25519_signature_verifies() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let parsed = PrivateKey::from_openssh(pem.as_bytes()).unwrap();
        verify(
            &key,
            b"challenge",
            &sign_with(&parsed, b"challenge", 0).unwrap(),
        );
    }

    #[test]
    fn ecdsa_p256_signature_verifies() {
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", 0).unwrap(),
        );
    }

    #[test]
    fn rsa_honours_sha2_flags() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap();
        let sig = verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", RSA_SHA2_512).unwrap(),
        );
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        let sig = verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", RSA_SHA2_256).unwrap(),
        );
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
    }

    #[test]
    fn decodes_purpose() {
        let mut login = Vec::new();
        put_string(&mut login, b"session-id");
        login.push(50);
        put_string(&mut login, b"git");
        put_string(&mut login, b"ssh-connection");
        put_string(&mut login, b"publickey");
        login.push(1);
        assert_eq!(purpose(&login), Purpose::Login { user: "git".into() });

        let mut sig = b"SSHSIG".to_vec();
        put_string(&mut sig, b"git");
        assert_eq!(
            purpose(&sig),
            Purpose::Sig {
                namespace: "git".into()
            }
        );
        assert_eq!(purpose(b"random"), Purpose::Unknown);
        assert_eq!(purpose(b""), Purpose::Unknown);
        assert_eq!(
            describe(
                &Purpose::Login {
                    user: "root".into()
                },
                Some("vps")
            )
            .0,
            "Log in to vps?"
        );
    }

    #[test]
    fn session_bind_detects_forwarding() {
        let bind = |forwarding: u8| {
            let mut b = Vec::new();
            put_string(&mut b, b"hostkey-blob");
            put_string(&mut b, b"session-id");
            put_string(&mut b, b"signature");
            b.push(forwarding);
            b
        };
        assert_eq!(
            parse_session_bind(&bind(0)),
            Some((b"hostkey-blob".to_vec(), false))
        );
        assert_eq!(
            parse_session_bind(&bind(1)),
            Some((b"hostkey-blob".to_vec(), true))
        );
        // Truncated before the flag: rejected, not treated as "not forwarded".
        let mut truncated = bind(1);
        truncated.pop();
        assert_eq!(parse_session_bind(&truncated), None);
        assert_eq!(parse_session_bind(b""), None);
    }

    #[test]
    fn malformed_input_is_rejected_not_panicking() {
        let mut r = Reader(&[0, 0, 0, 9, 1, 2]);
        assert!(r.string().is_err());
        assert!(Reader(&[]).u32().is_err());
        assert!(Reader(&[]).byte().is_err());
    }

    #[test]
    fn prompts_and_replies() {
        let agent = SshAgent::default();
        agent.pending.lock().unwrap().insert(
            7,
            Pending {
                prompt: Prompt {
                    id: 7,
                    title: "t".into(),
                    action: "a".into(),
                    key_name: "k".into(),
                    fingerprint: "f".into(),
                    client: "c".into(),
                    command: "cmd".into(),
                    forwarded: false,
                    can_remember: true,
                },
                decision: None,
            },
        );
        assert_eq!(agent.pending().len(), 1);
        assert!(agent.reply(
            7,
            Decision {
                approve: true,
                remember: false
            }
        ));
        assert!(
            !agent.reply(7, Decision::default()),
            "a prompt can only be answered once"
        );
        assert!(agent.pending().is_empty());
        assert!(!agent.reply(99, Decision::default()));
    }

    #[test]
    fn approvals_reset_when_the_session_changes() {
        let agent = SshAgent::default();
        let s1 = Some(Instant::now());
        agent.approve(s1, "fp|/usr/bin/ssh".into());
        assert!(agent.is_approved(s1, "fp|/usr/bin/ssh"));
        let s2 = Some(Instant::now() + Duration::from_secs(1));
        assert!(!agent.is_approved(s2, "fp|/usr/bin/ssh"));
        assert!(!agent.is_approved(None, "fp|/usr/bin/ssh"));
    }
}
