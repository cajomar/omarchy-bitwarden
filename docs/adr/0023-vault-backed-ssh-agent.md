# ADR 0023: Vault-Backed OpenSSH Agent with Notification Prompts

## Status
Proposed

## Context
`omawarden` could generate, import and export SSH keys (ADR 0005) but could not use them: keys had to be exported to disk or loaded into another agent. The README lists the missing OpenSSH agent as a gap compared with `rbw`.

The goal is for vault SSH keys to work like a native session agent: nothing to start after login, no keys on disk, and a prompt only when a key is actually used.

## Decision
1. **Agent inside the daemon**: when `ssh_agent_enabled` is set, the daemon serves the OpenSSH agent protocol on `$XDG_RUNTIME_DIR/omawarden-ssh-agent.sock` (`0600`, peer UID verified). `SSH_AUTH_SOCK` is exported through `~/.config/uwsm/env.d`. Private keys are parsed only for the duration of one signature and are zeroized afterwards. Adding, removing and locking keys through the agent protocol is refused; the vault owns them.
2. **Unlock on demand**: a request while the vault is locked opens the overlay (a password cannot be entered in a notification) and posts a "Vault locked" notification; clicking it reopens the unlock screen. One prompt is shown however many clients are waiting; requests wait up to 60 seconds.
3. **Approval by system notification**: signing posts a notification showing the host, key, requesting program and whether approval is remembered. Clicking it opens the overlay approval card; on servers that render action buttons, Approve and Deny answer directly. Omarchy's server advertises actions but only fires `default` on click, so a dismissal must not count as Deny: dismissed or expired notifications leave the prompt pending until its 60-second timeout. `ssh_agent_confirm` is `always`, `first-use` (once per key and program until the daemon exits at logout; vault re-locks don't reset it, since unlocking already proves presence) or `never`. Requests forwarded through `session-bind@openssh.com` are always confirmed.
4. **Activity**: a completed signature counts as vault activity, so active use does not idle-lock. Listing keys does not, because any process of the same user can do that and it must not keep the vault unlocked (Security Handbook Rule 9).
5. **Daemon lifecycle**: a daemon built from a different commit is replaced only while the vault is locked. Replacing an unlocked daemon would lock the vault and drop the agent socket mid-use.
6. **Lock model unchanged**: the vault still locks on idle timeout, screen lock, suspend and the maximum session lifetime, and is unlocked with the master password.

## Alternatives Considered
- **`ssh-add` keys into the stock `ssh-agent` on unlock**: far less code, but keys are loaded only after a manual unlock, so `ssh` cannot trigger one; keys leave the daemon's `mlock`/`zeroize` protection; per-host and per-program prompts are lost.
- **Separate agent process**: cleaner lifecycle, but it still needs the daemon for keys and signing, and does not change the user-visible behaviour.
- **Keyring or polkit-backed unlock** (as Bitwarden's desktop app does): would make unlocking silent or a system prompt, at the cost of the vault being only as strong as the login. Not adopted here; it changes the security model and should be decided separately.

## Consequences
- **Positive**: `ssh`, `git` signing and `ssh-keygen -Y sign` use vault keys with no files on disk and no manual agent management.
- **Trade-off**: the master password is still required after each lock, so a session that screen-locks or suspends will ask again on the next use.
- **Trade-off**: after an upgrade the old daemon keeps running until the vault locks, so new daemon actions may be unavailable until then.
- **Requirement**: prompts need a notification server with action support and `notify-send`; without one the overlay card is used.
