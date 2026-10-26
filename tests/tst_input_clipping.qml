import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components" as Components

Item {
  id: testRunner
  width: 800
  height: 600

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  function findTextInputs(item, list) {
    if (!item) return
    // In QML / QtQuick, TextInput items have 'text' and 'selectByMouse' and 'echoMode'
    if (item.toString().indexOf("QQuickTextInput") !== -1 || (item.hasOwnProperty("echoMode") && item.hasOwnProperty("selectByMouse"))) {
      list.push(item)
    }
    if (item.children) {
      for (var i = 0; i < item.children.length; i++) {
        findTextInputs(item.children[i], list)
      }
    }
  }

  Components.AuthView {
    id: authView
    width: 400
    height: 600
    showServerConfig: true
    enableMtlsChecked: true
  }

  Components.SettingsModal {
    id: settingsModal
    width: 600
    height: 700
    visible: true
    enableMtlsChecked: true
  }

  Components.SshKeyModal {
    id: sshKeyModal
    width: 600
    height: 700
    active: true
  }

  Component.onCompleted: {
    console.log("Running Input Clipping Tests...")

    var authInputs = []
    findTextInputs(authView, authInputs)
    console.log("Found", authInputs.length, "TextInput(s) in AuthView")
    for (var i = 0; i < authInputs.length; i++) {
      var input = authInputs[i]
      var textVal = input.text ? input.text : (input.placeholderText || "input_" + i)
      check(input.clip === true, "AuthView TextInput (" + textVal + ") must have clip: true")
    }

    var settingsInputs = []
    findTextInputs(settingsModal, settingsInputs)
    console.log("Found", settingsInputs.length, "TextInput(s) in SettingsModal")
    for (var j = 0; j < settingsInputs.length; j++) {
      var sInput = settingsInputs[j]
      var sTextVal = sInput.text ? sInput.text : (sInput.placeholderText || "input_" + j)
      check(sInput.clip === true, "SettingsModal TextInput (" + sTextVal + ") must have clip: true")
    }

    var sshInputs = []
    findTextInputs(sshKeyModal, sshInputs)
    console.log("Found", sshInputs.length, "TextInput(s) in SshKeyModal")
    for (var k = 0; k < sshInputs.length; k++) {
      var kInput = sshInputs[k]
      var kTextVal = kInput.text ? kInput.text : (kInput.placeholderText || "input_" + k)
      check(kInput.clip === true, "SshKeyModal TextInput (" + kTextVal + ") must have clip: true")
    }

    if (failures > 0) {
      console.error("TOTAL FAILURES:", failures)
    } else {
      console.log("ALL INPUT CLIPPING TESTS PASSED!")
    }
    Qt.quit()
  }
}

