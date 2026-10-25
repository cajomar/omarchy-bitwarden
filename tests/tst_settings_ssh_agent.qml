import QtQuick
import QtQuick.Controls
import "../components"

Item {
  property int failures: 0
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

  SettingsModal { id: sm }

  Component.onCompleted: {
    // Defaults: off, confirm on first use
    check(sm.sshAgentChecked === false, "SSH agent is off by default")
    check(sm.sshAgentConfirm === "first-use", "confirmation defaults to first-use")

    // Config drives the controls
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", ssh_agent_enabled: true, ssh_agent_confirm: "always" })
    check(sm.sshAgentChecked === true, "config ssh_agent_enabled:true checks the box")
    check(sm.sshAgentConfirm === "always", "config ssh_agent_confirm is reflected")

    // Older configs without the keys turn it off and keep the current policy
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error" })
    check(sm.sshAgentChecked === false, "config without ssh_agent_enabled leaves it off")
    check(sm.sshAgentConfirm === "always", "config without ssh_agent_confirm keeps the last value")

    // Payload carries both
    sm.sshAgentChecked = true
    sm.sshAgentConfirm = "never"
    var payload = sm.buildPayload()
    check(payload.ssh_agent_enabled === true, "payload ssh_agent_enabled reflects the checkbox")
    check(payload.ssh_agent_confirm === "never", "payload ssh_agent_confirm reflects the choice")
    check(payload.server_url !== undefined, "existing keys still present")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
