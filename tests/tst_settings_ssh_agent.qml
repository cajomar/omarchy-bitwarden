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

    // Style parity with logging severity level
    var confirmItem0 = sm.confirmRepeater.itemAt(0)
    var logItem0 = sm.logSeverityRepeater.itemAt(0)
    check(confirmItem0 !== null, "confirm options item exists")
    check(logItem0 !== null, "log level item exists")
    if (confirmItem0 && logItem0) {
      check(confirmItem0.implicitHeight === logItem0.implicitHeight, "confirm option height matches logging level (" + confirmItem0.implicitHeight + " == " + logItem0.implicitHeight + ")")
      check(confirmItem0.radius === logItem0.radius, "confirm option radius matches logging level (" + confirmItem0.radius + " == " + logItem0.radius + ")")
      check(confirmItem0.border.width === logItem0.border.width, "confirm option border width matches logging level")
      console.log("PASS: confirm options styling matches logging severity level")
    }

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
