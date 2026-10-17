//! OpenSSH agent backed by the vault's SSH key items.
//!
//! The daemon listens on `$XDG_RUNTIME_DIR/omawarden-ssh-agent.sock` when
//! `ssh_agent_enabled` is set. Private keys are parsed only for the duration
//! of a single signature. Signing asks for confirmation in the Omarchy overlay
//! according to `ssh_agent_confirm`:
//!
//! - `always`: every signature
//! - `first-use` (default): once per key, client program and the app it runs
//!   in (terminal, editor…), until the daemon exits (normally at logout);
//!   re-locking the vault does not reset it
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
    /// Whether approving is remembered for this key, program and app until
    /// logout (first-use policy and not forwarded), so the UI can say so.
    pub remembered: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Decision {
    pub approve: bool,
}

struct Pending {
    prompt: Prompt,
    decision: Option<Decision>,
}

pub struct SshAgent {
    pending: Mutex<HashMap<u64, Pending>>,
    answered: Condvar,
    next_id: AtomicU64,
    /// Approved "fingerprint|client exe|app exe" triples. They outlive vault locks:
    /// the vault re-locks on every screen lock, and unlocking already proves
    /// presence, so asking again each time adds nothing.
    approvals: Mutex<HashSet<String>>,
    /// Whether the socket is currently bound.
    running: std::sync::atomic::AtomicBool,
    /// An unlock prompt is already on screen.
    unlock_prompted: std::sync::atomic::AtomicBool,
    prompt_timeout: Duration,
    unlock_timeout: Duration,
}

impl Default for SshAgent {
    fn default() -> Self {
        SshAgent {
            pending: Mutex::new(HashMap::new()),
            answered: Condvar::new(),
            next_id: AtomicU64::new(1),
            approvals: Mutex::new(HashSet::new()),
            running: std::sync::atomic::AtomicBool::new(false),
            unlock_prompted: std::sync::atomic::AtomicBool::new(false),
            prompt_timeout: PROMPT_TIMEOUT,
            unlock_timeout: UNLOCK_TIMEOUT,
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

    fn is_approved(&self, key: &str) -> bool {
        self.approvals.lock().is_ok_and(|a| a.contains(key))
    }

    fn approve(&self, key: String) {
        if let Ok(mut a) = self.approvals.lock() {
            a.insert(key);
        }
    }
}

/// Post a prompt and wait for its answer; no answer within the timeout denies.
fn ask(host: &Arc<dyn Host>, mut prompt: Prompt) -> Decision {
    let agent = host.agent();
    let id = agent.next_id.fetch_add(1, Ordering::Relaxed);
    prompt.id = id;
    let (title, body) = notification_text(&prompt);
    if let Ok(mut pending) = agent.pending.lock() {
        pending.insert(
            id,
            Pending {
                prompt,
                decision: None,
            },
        );
    }
    // A system notification. Servers that render buttons get Approve and
    // Deny; Omarchy's only fires "default" on click, which opens the overlay
    // card. Dismissing or expiring answers nothing: the prompt stays pending
    // (and answerable in the overlay) until it times out.
    let h = host.clone();
    let spawned = host.notify(
        &title,
        &body,
        &[
            ("default", "Review"),
            ("approve", "Approve"),
            ("deny", "Deny"),
        ],
        agent.prompt_timeout,
        Box::new(move |action| match action {
            "approve" | "deny" => {
                h.agent().reply(
                    id,
                    Decision {
                        approve: action == "approve",
                    },
                );
            }
            "default" => h.summon_overlay(&serde_json::json!({ "view": "ssh-approval", "id": id })),
            _ => {}
        }),
    );
    if !spawned {
        host.summon_overlay(&serde_json::json!({ "view": "ssh-approval", "id": id }));
    }

    let deadline = Instant::now() + agent.prompt_timeout;
    let Ok(mut pending) = agent.pending.lock() else {
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
        match agent.answered.wait_timeout(pending, deadline - now) {
            Ok((guard, _)) => pending = guard,
            Err(_) => return Decision::default(),
        }
    };
    pending.remove(&id);
    decision
}

/// Notification text for a pending signature.
fn notification_text(p: &Prompt) -> (String, String) {
    let mut body = format!(
        "{} \u{2014} key \"{}\"\nRequested by {}",
        p.action, p.key_name, p.client
    );
    if p.forwarded {
        body.push_str("\nForwarded from a remote host");
    } else if p.remembered {
        body.push_str(&format!(
            "\nApproval is remembered for {} until you log out",
            p.client
        ));
    }
    (p.title.clone(), body)
}

/// Show a system notification with action buttons and hand the chosen action
/// (empty when dismissed or expired) to `on_action` from a worker thread.
/// Returns false if `notify-send` couldn't be started.
fn notify(
    title: &str,
    body: &str,
    actions: &[(&str, &str)],
    timeout: Duration,
    on_action: impl FnOnce(&str) + Send + 'static,
) -> bool {
    let mut cmd = std::process::Command::new("notify-send");
    cmd.args([
        "--app-name=Bitwarden",
        "--icon=dialog-password",
        "--urgency=critical",
    ])
    .arg(format!("--expire-time={}", timeout.as_millis()));
    for (name, label) in actions {
        cmd.arg("-A").arg(format!("{name}={label}"));
    }
    cmd.arg(title)
        .arg(body)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let Ok(child) = cmd.spawn() else {
        return false;
    };
    std::thread::spawn(move || {
        let action = child
            .wait_with_output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        on_action(&action);
    });
    true
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

/// What the agent needs from the daemon and the desktop. The daemon is the
/// real host; tests drive the protocol against a fake one.
trait Host: Send + Sync + 'static {
    fn agent(&self) -> &Arc<SshAgent>;
    fn is_unlocked(&self) -> bool;
    fn keys(&self) -> Vec<AgentKey>;
    fn policy(&self) -> Confirm;
    /// A signature was made (keeps the vault from idle-locking).
    fn record_activity(&self);
    fn known_host(&self, hostkey: &[u8]) -> Option<String>;
    /// See [`notify`].
    fn notify(
        &self,
        title: &str,
        body: &str,
        actions: &[(&str, &str)],
        timeout: Duration,
        on_action: Box<dyn FnOnce(&str) + Send>,
    ) -> bool;
    fn summon_overlay(&self, payload: &serde_json::Value);
}

impl Host for DaemonState {
    fn agent(&self) -> &Arc<SshAgent> {
        &self.ssh_agent
    }
    fn is_unlocked(&self) -> bool {
        self.vault_mgr.is_unlocked()
    }
    fn keys(&self) -> Vec<AgentKey> {
        vault_keys(self)
    }
    fn policy(&self) -> Confirm {
        Confirm::parse(
            &crate::config::ConfigManager::default()
                .load()
                .ssh_agent_confirm,
        )
    }
    fn record_activity(&self) {
        self.touch_activity();
    }
    fn known_host(&self, hostkey: &[u8]) -> Option<String> {
        known_host_for(hostkey)
    }
    fn notify(
        &self,
        title: &str,
        body: &str,
        actions: &[(&str, &str)],
        timeout: Duration,
        on_action: Box<dyn FnOnce(&str) + Send>,
    ) -> bool {
        notify(title, body, actions, timeout, on_action)
    }
    fn summon_overlay(&self, payload: &serde_json::Value) {
        summon_overlay(payload)
    }
}

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
    let host: Arc<dyn Host> = state;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if !host.agent().running.load(Ordering::SeqCst) {
                break;
            }
            match stream {
                Ok(stream) => {
                    let host = host.clone();
                    std::thread::spawn(move || {
                        let served =
                            crate::daemon::verify_peer_credentials(&stream).and_then(|_| {
                                let peer = Peer::of(&stream);
                                serve(&host, stream, peer)
                            });
                        if let Err(e) = served {
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

fn serve(host: &Arc<dyn Host>, mut stream: impl Read + Write, peer: Peer) -> std::io::Result<()> {
    let mut conn = Conn {
        peer,
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
            REQUEST_IDENTITIES => send(&mut stream, IDENTITIES_ANSWER, &identities(host))?,
            SIGN_REQUEST => match sign(host, &conn, body) {
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
                            conn.host = host.known_host(&hostkey);
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

fn send(stream: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
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
fn wait_for_unlock(host: &Arc<dyn Host>) -> bool {
    if host.is_unlocked() {
        return true;
    }
    let agent = host.agent();
    // One unlock prompt at a time, however many ssh processes are waiting.
    if !agent.unlock_prompted.swap(true, Ordering::SeqCst) {
        host.summon_overlay(&serde_json::json!({}));
        let h = host.clone();
        let spawned = host.notify(
            "Vault locked",
            "An SSH key was requested. Unlock your vault to continue.",
            &[("default", "Unlock")],
            agent.unlock_timeout,
            Box::new(move |action| {
                if action == "default" {
                    h.summon_overlay(&serde_json::json!({}));
                }
                h.agent().unlock_prompted.store(false, Ordering::SeqCst);
            }),
        );
        if !spawned {
            agent.unlock_prompted.store(false, Ordering::SeqCst);
        }
    }
    let deadline = Instant::now() + agent.unlock_timeout;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        if host.is_unlocked() {
            agent.unlock_prompted.store(false, Ordering::SeqCst);
            return true;
        }
    }
    false
}

fn identities(host: &Arc<dyn Host>) -> Vec<u8> {
    let keys = if wait_for_unlock(host) {
        host.keys()
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

fn sign(host: &Arc<dyn Host>, conn: &Conn, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader(body);
    let key_blob = r.string()?.to_vec();
    let data = r.string()?.to_vec();
    let flags = r.u32().unwrap_or(0);

    if !wait_for_unlock(host) {
        return Err("vault is locked".into());
    }
    let key = host
        .keys()
        .into_iter()
        .find(|k| k.blob == key_blob)
        .ok_or("key not in vault")?;

    let agent = host.agent();
    let policy = host.policy();
    let remember_key = format!("{}|{}|{}", key.fingerprint, conn.peer.exe, conn.peer.app);
    let needs_prompt = conn.forwarded
        || match policy {
            Confirm::Never => false,
            Confirm::Always => true,
            Confirm::FirstUse => !agent.is_approved(&remember_key),
        };
    if needs_prompt {
        let (title, action) = describe(&purpose(&data), conn.host.as_deref());
        let decision = ask(
            host,
            Prompt {
                id: 0,
                title,
                action,
                key_name: key.name.clone(),
                fingerprint: key.fingerprint.clone(),
                client: conn.peer.describe(),
                command: conn.peer.cmdline.clone(),
                forwarded: conn.forwarded,
                remembered: policy == Confirm::FirstUse && !conn.forwarded,
            },
        );
        if !decision.approve {
            return Err("denied".into());
        }
        if policy == Confirm::FirstUse && !conn.forwarded {
            agent.approve(remember_key);
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
    // Only a completed signature counts as activity: listing keys is open to
    // any process of this user and must not keep the vault unlocked.
    let signature = sign_with(&private, &data, flags)?;
    host.record_activity();
    Ok(signature)
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
        let publickey = method == b"publickey" || method == b"publickey-hostbound-v00@openssh.com";
        if service != b"ssh-connection" || !publickey {
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
    /// Executable of the app the request comes from (see [`Peer::find_app`]).
    app: String,
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
            let mut peer = Peer::from_pid(cred.pid);
            peer.app = peer.find_app();
            peer
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
            app: String::new(),
        }
    }

    /// The first ancestor that isn't a shell or an ssh/git wrapper: the
    /// terminal, editor or tool the person is using. Remembered approvals are
    /// scoped to it, so approving `ssh` in a terminal doesn't approve every
    /// other program that runs `ssh`. Read from `exe` links, which a process
    /// can't rename.
    fn find_app(&self) -> String {
        let mut next = self.parent();
        for _ in 0..16 {
            let Some(p) = next else { break };
            if !is_wrapper(&p.exe) {
                return p.exe;
            }
            next = p.parent();
        }
        String::new()
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
        let app = Path::new(&self.app)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !app.is_empty() && !who.starts_with(&app) {
            who = format!("{who} in {app}");
        }
        who
    }
}

fn is_wrapper(exe: &str) -> bool {
    let name = Path::new(exe)
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    matches!(
        name.as_ref(),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "nu" | "ssh" | "git" | "ssh-keygen"
    )
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
    fn notification_text_reflects_policy() {
        let mut p = Prompt {
            id: 1,
            title: "Log in to github.com?".into(),
            action: "SSH login as git@github.com".into(),
            key_name: "Work".into(),
            fingerprint: String::new(),
            client: "git (ssh)".into(),
            command: String::new(),
            forwarded: false,
            remembered: true,
        };
        let (title, body) = notification_text(&p);
        assert_eq!(title, "Log in to github.com?");
        assert!(body.contains("git@github.com") && body.contains("\"Work\""));
        assert!(body.contains("until you log out"));
        p.forwarded = true;
        assert!(notification_text(&p).1.contains("Forwarded"));
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

        let mut hostbound = Vec::new();
        put_string(&mut hostbound, b"session-id");
        hostbound.push(50);
        put_string(&mut hostbound, b"git");
        put_string(&mut hostbound, b"ssh-connection");
        put_string(&mut hostbound, b"publickey-hostbound-v00@openssh.com");
        hostbound.push(1);
        assert_eq!(purpose(&hostbound), Purpose::Login { user: "git".into() });

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
                    remembered: true,
                },
                decision: None,
            },
        );
        assert_eq!(agent.pending().len(), 1);
        assert!(agent.reply(7, Decision { approve: true }));
        assert!(
            !agent.reply(7, Decision::default()),
            "a prompt can only be answered once"
        );
        assert!(agent.pending().is_empty());
        assert!(!agent.reply(99, Decision::default()));
    }

    #[test]
    fn wrappers_are_skipped_when_finding_the_app() {
        assert!(is_wrapper("/usr/bin/zsh"));
        assert!(is_wrapper("/usr/bin/ssh"));
        assert!(is_wrapper("/usr/bin/git"));
        assert!(!is_wrapper("/usr/bin/ghostty"));
        assert!(!is_wrapper("/usr/bin/lazygit"));
        assert!(!is_wrapper(""));
        let peer = |comm: &str, app: &str| Peer {
            comm: comm.into(),
            app: app.into(),
            ..Peer::default()
        };
        assert_eq!(peer("ssh", "/usr/bin/ghostty").describe(), "ssh in ghostty");
        assert_eq!(peer("lazygit", "/usr/bin/lazygit").describe(), "lazygit");
        assert_eq!(peer("ssh", "").describe(), "ssh");
    }

    #[test]
    fn find_app_walks_past_shells_to_the_launching_program() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 5; true"])
            .spawn()
            .unwrap();
        let sh = child.id() as i32;
        let sleep = (0..100)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(10));
                fs::read_to_string(format!("/proc/{sh}/task/{sh}/children"))
                    .ok()?
                    .split_whitespace()
                    .next()?
                    .parse::<i32>()
                    .ok()
            })
            .unwrap();
        let app = Peer::from_pid(sleep).find_app();
        let _ = child.kill();
        let _ = child.wait();
        let ours = fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(app, ours.to_string_lossy());
    }

    // -- Protocol tests against a fake vault and notification server --------

    /// What the fake notification server does with a prompt.
    #[derive(Clone, Copy)]
    enum Notifier {
        /// Fires this action (Omarchy: "default" on click, "" on dismiss).
        Answer(&'static str),
        /// Stays on screen until it expires.
        Silent,
        /// notify-send is missing.
        Unavailable,
    }

    struct FakeHost {
        agent: Arc<SshAgent>,
        unlocked: std::sync::atomic::AtomicBool,
        keys: Vec<(String, PrivateKey)>,
        policy: Mutex<Confirm>,
        notifier: Mutex<Notifier>,
        activity: AtomicU64,
        notifications: Mutex<Vec<String>>,
        overlays: Mutex<Vec<serde_json::Value>>,
    }

    impl FakeHost {
        fn new(policy: Confirm, notifier: Notifier) -> Arc<FakeHost> {
            Arc::new(FakeHost {
                agent: Arc::new(SshAgent {
                    prompt_timeout: Duration::from_millis(400),
                    unlock_timeout: Duration::from_millis(400),
                    ..SshAgent::default()
                }),
                unlocked: true.into(),
                keys: vec![(
                    "Work".into(),
                    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
                )],
                policy: Mutex::new(policy),
                notifier: Mutex::new(notifier),
                activity: AtomicU64::new(0),
                notifications: Mutex::new(Vec::new()),
                overlays: Mutex::new(Vec::new()),
            })
        }
        fn notifications(&self) -> Vec<String> {
            self.notifications.lock().unwrap().clone()
        }
        fn overlays(&self) -> Vec<serde_json::Value> {
            self.overlays.lock().unwrap().clone()
        }
        fn activity(&self) -> u64 {
            self.activity.load(Ordering::SeqCst)
        }
    }

    impl Host for FakeHost {
        fn agent(&self) -> &Arc<SshAgent> {
            &self.agent
        }
        fn is_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
        fn keys(&self) -> Vec<AgentKey> {
            self.keys
                .iter()
                .map(|(name, key)| AgentKey {
                    name: name.clone(),
                    blob: blob_of(&key.public_key().to_openssh().unwrap()).unwrap(),
                    fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                    private_key: key.to_openssh(LineEnding::LF).unwrap(),
                    passphrase: None,
                })
                .collect()
        }
        fn policy(&self) -> Confirm {
            *self.policy.lock().unwrap()
        }
        fn record_activity(&self) {
            self.activity.fetch_add(1, Ordering::SeqCst);
        }
        fn known_host(&self, _hostkey: &[u8]) -> Option<String> {
            Some("vps".into())
        }
        fn notify(
            &self,
            title: &str,
            _body: &str,
            _actions: &[(&str, &str)],
            _timeout: Duration,
            on_action: Box<dyn FnOnce(&str) + Send>,
        ) -> bool {
            let notifier = *self.notifier.lock().unwrap();
            if matches!(notifier, Notifier::Unavailable) {
                return false;
            }
            self.notifications.lock().unwrap().push(title.into());
            if let Notifier::Answer(action) = notifier {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    on_action(action);
                });
            }
            true
        }
        fn summon_overlay(&self, payload: &serde_json::Value) {
            self.overlays.lock().unwrap().push(payload.clone());
        }
    }

    /// An ssh-like client connected to a fresh agent connection.
    struct Client(UnixStream);

    impl Client {
        fn connect(host: &Arc<FakeHost>, exe: &str, app: &str) -> Client {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let host: Arc<dyn Host> = host.clone();
            let peer = Peer {
                exe: exe.into(),
                comm: "ssh".into(),
                app: app.into(),
                ..Peer::default()
            };
            std::thread::spawn(move || serve(&host, theirs, peer));
            Client(ours)
        }
        fn request(&mut self, kind: u8, body: &[u8]) -> (u8, Vec<u8>) {
            send(&mut self.0, kind, body).unwrap();
            let mut len = [0u8; 4];
            self.0.read_exact(&mut len).unwrap();
            let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
            self.0.read_exact(&mut msg).unwrap();
            (msg[0], msg[1..].to_vec())
        }
        fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
            let (kind, body) = self.request(REQUEST_IDENTITIES, &[]);
            assert_eq!(kind, IDENTITIES_ANSWER);
            let mut r = Reader(&body);
            (0..r.u32().unwrap())
                .map(|_| {
                    let blob = r.string().unwrap().to_vec();
                    let name = String::from_utf8_lossy(r.string().unwrap()).into_owned();
                    (blob, name)
                })
                .collect()
        }
        /// Sign a login challenge with the first key; the signature on success.
        fn sign(&mut self, host: &FakeHost) -> Option<Vec<u8>> {
            let blob = host.keys()[0].blob.clone();
            let mut body = Vec::new();
            put_string(&mut body, &blob);
            put_string(&mut body, LOGIN);
            body.extend_from_slice(&0u32.to_be_bytes());
            match self.request(SIGN_REQUEST, &body) {
                (SIGN_RESPONSE, sig) => Some(Reader(&sig).string().unwrap().to_vec()),
                (FAILURE, _) => None,
                (kind, _) => panic!("unexpected reply {kind}"),
            }
        }
        fn session_bind(&mut self, forwarding: bool) -> u8 {
            let mut body = Vec::new();
            put_string(&mut body, b"session-bind@openssh.com");
            put_string(&mut body, b"hostkey-blob");
            put_string(&mut body, b"session-id");
            put_string(&mut body, b"signature");
            body.push(forwarding as u8);
            self.request(EXTENSION, &body).0
        }
    }

    const LOGIN: &[u8] =
        b"\0\0\0\x02id\x32\0\0\0\x04root\0\0\0\x0essh-connection\0\0\0\x09publickey";

    const SSH: &str = "/usr/bin/ssh";
    const TERMINAL: &str = "/usr/bin/ghostty";

    #[test]
    fn signatures_verify_and_count_as_activity_but_listing_does_not() {
        let host = FakeHost::new(Confirm::Never, Notifier::Silent);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        let ids = c.identities();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].1, "Work");
        assert_eq!(
            host.activity(),
            0,
            "listing keys must not keep the vault awake"
        );

        let sig = c.sign(&host).expect("never policy signs without asking");
        verify(&host.keys[0].1, LOGIN, &sig);
        assert_eq!(host.activity(), 1);
        assert!(host.notifications().is_empty());
    }

    #[test]
    fn first_use_asks_once_per_key_program_and_app() {
        let host = FakeHost::new(Confirm::FirstUse, Notifier::Answer("approve"));
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.notifications().len(), 1, "second use is remembered");

        // Same terminal, new connection: still remembered.
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        assert_eq!(host.notifications().len(), 1);

        // The same ssh binary run by another app asks again.
        assert!(Client::connect(&host, SSH, "/usr/bin/python3")
            .sign(&host)
            .is_some());
        assert_eq!(host.notifications().len(), 2);
    }

    #[test]
    fn locking_the_vault_keeps_first_use_approvals() {
        let host = FakeHost::new(Confirm::FirstUse, Notifier::Answer("approve"));
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        host.unlocked.store(false, Ordering::SeqCst);
        let h = host.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            h.unlocked.store(true, Ordering::SeqCst);
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        let titles = host.notifications();
        assert_eq!(titles.len(), 2);
        assert_eq!(
            titles[1], "Vault locked",
            "only the unlock prompt, no re-approval"
        );
    }

    #[test]
    fn always_asks_every_time_and_deny_refuses() {
        let host = FakeHost::new(Confirm::Always, Notifier::Answer("approve"));
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.notifications().len(), 2);

        *host.notifier.lock().unwrap() = Notifier::Answer("deny");
        assert!(c.sign(&host).is_none());
        assert_eq!(host.activity(), 2, "a refused signature is not activity");
    }

    #[test]
    fn forwarded_requests_always_ask_and_are_never_remembered() {
        let host = FakeHost::new(Confirm::Never, Notifier::Answer("approve"));
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert_eq!(c.session_bind(true), SUCCESS);
        assert!(c.sign(&host).is_some());
        assert_eq!(host.notifications(), vec!["Log in to vps?".to_string()]);

        *host.policy.lock().unwrap() = Confirm::FirstUse;
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.notifications().len(), 3);
        assert!(!host.agent.approvals.lock().unwrap().iter().any(|_| true));

        // A later non-forwarding bind on the same connection doesn't clear it.
        assert_eq!(c.session_bind(false), SUCCESS);
        assert!(c.sign(&host).is_some());
        assert_eq!(host.notifications().len(), 4);
    }

    #[test]
    fn dismissing_a_notification_is_not_a_denial() {
        let host = FakeHost::new(Confirm::Always, Notifier::Answer(""));
        let h = host.clone();
        let approver = std::thread::spawn(move || loop {
            if let Some(p) = h.agent.pending().first() {
                // Answered later from the overlay card.
                std::thread::sleep(Duration::from_millis(100));
                return h.agent.reply(p.id, Decision { approve: true });
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        assert!(approver.join().unwrap());
    }

    #[test]
    fn clicking_a_notification_opens_the_approval_card() {
        let host = FakeHost::new(Confirm::Always, Notifier::Answer("default"));
        // Nobody answers the card: the prompt times out and is refused.
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        let overlays = host.overlays();
        assert_eq!(overlays.len(), 1);
        assert_eq!(overlays[0]["view"], "ssh-approval");
        assert!(
            host.agent.pending().is_empty(),
            "timed-out prompts are removed"
        );
    }

    #[test]
    fn without_notifications_the_card_opens_directly() {
        let host = FakeHost::new(Confirm::Always, Notifier::Unavailable);
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        assert_eq!(host.overlays()[0]["view"], "ssh-approval");
    }

    #[test]
    fn locked_vault_prompts_once_and_gives_up_after_the_timeout() {
        let host = FakeHost::new(Confirm::Never, Notifier::Silent);
        host.unlocked.store(false, Ordering::SeqCst);
        let clients: Vec<_> = (0..3)
            .map(|_| {
                let h = host.clone();
                std::thread::spawn(move || Client::connect(&h, SSH, TERMINAL).identities())
            })
            .collect();
        for c in clients {
            assert!(c.join().unwrap().is_empty(), "no keys while locked");
        }
        assert_eq!(host.notifications(), vec!["Vault locked".to_string()]);
        assert_eq!(host.overlays().len(), 1);
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
    }

    #[test]
    fn key_management_and_unknown_requests_are_refused() {
        let host = FakeHost::new(Confirm::Never, Notifier::Silent);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        for kind in [17u8, 18, 19, 22, 23] {
            // add, remove, remove-all, lock, unlock
            assert_eq!(c.request(kind, &[]).0, FAILURE);
        }
        let mut ext = Vec::new();
        put_string(&mut ext, b"unknown@example.com");
        assert_eq!(c.request(EXTENSION, &ext).0, EXTENSION_FAILURE);

        let mut bogus = Vec::new();
        put_string(&mut bogus, b"not-a-key");
        put_string(&mut bogus, b"data");
        assert_eq!(c.request(SIGN_REQUEST, &bogus).0, FAILURE);
        // Still usable afterwards.
        assert_eq!(c.identities().len(), 1);
    }

    #[test]
    fn oversized_messages_close_the_connection() {
        let host = FakeHost::new(Confirm::Never, Notifier::Silent);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        c.0.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes())
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(c.0.read(&mut buf).unwrap(), 0);
    }
}
