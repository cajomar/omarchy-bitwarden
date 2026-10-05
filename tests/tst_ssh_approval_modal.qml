import QtQuick
import QtQuick.Controls
import "../components"

Item {
  width: 800; height: 600
  property int failures: 0
  property var replies: []
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

  SshApprovalModal {
    id: modal
    onReplyRequested: function(approve) { replies.push(approve) }
  }

  Component.onCompleted: {
    // Hidden until the overlay is open and a prompt exists
    check(modal.visible === false, "hidden with no prompt")
    modal.active = true
    check(modal.visible === false, "hidden when active but no prompt")

    modal.prompt = ({ id: 1, title: "Sign with Git?", action: "Git commit or tag signature", key_name: "Work", fingerprint: "SHA256:abc",
                      client: "git (ssh)", command: "ssh-keygen -Y sign", forwarded: false, remembered: true })
    check(modal.visible === true, "visible with a prompt")

    modal.active = false
    check(modal.visible === false, "hidden when the overlay closes")
    modal.active = true

    // Forwarded requests switch the card border to the danger color
    modal.prompt = ({ id: 2, title: "Log in to vps?", action: "SSH login as root@vps", key_name: "Work", fingerprint: "SHA256:abc",
                      client: "ssh", command: "ssh vps", forwarded: true, remembered: false })
    check(modal.visible === true, "forwarded prompt visible")

    // The reply signal carries approve/deny
    modal.replyRequested(true)
    modal.replyRequested(false)
    check(replies.length === 2 && replies[0] === true && replies[1] === false, "replyRequested carries the decision")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
