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

    // The card opens by itself: Allow is ignored until it has been up briefly
    replies = []
    check(modal.armed === false, "a new prompt starts unarmed")
    modal.allow()
    check(replies.length === 0, "allow is ignored before arming")
    armWait.start()
  }

  Timer {
    id: armWait
    interval: 800
    onTriggered: {
      check(modal.armed === true, "armed after the delay")
      // A polling refresh of the same prompt doesn't re-arm
      modal.prompt = Object.assign({}, modal.prompt)
      check(modal.armed === true, "refreshing the same prompt keeps it armed")
      modal.allow()
      check(replies.length === 1 && replies[0] === true, "allow approves once armed")

      // A different prompt starts unarmed again
      modal.prompt = Object.assign({}, modal.prompt, { id: 3 })
      check(modal.armed === false, "a new prompt re-arms")
      Qt.exit(failures === 0 ? 0 : 1)
    }
  }
}
