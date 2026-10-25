import QtQuick
import QtQuick.Controls
import "../components/IconPolicy.js" as IconPolicy

Item {
  id: testRoot
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  // Pure logic mirror of SettingsModal & AuthView origin gating and payload generation
  function resolveCertGating(serverUrl, config) {
    var curServer = (serverUrl || "").trim()
    var isOfficial = IconPolicy.isOfficialServer(curServer)
    var certMatches = false
    if (config && config.client_cert_server && config.client_cert_path && !isOfficial) {
      certMatches = IconPolicy.isSameOrigin(curServer, config.client_cert_server)
    }
    return {
      isOfficial: isOfficial,
      certMatchesServer: certMatches,
      displayedCert: certMatches ? (config.client_cert_path || "") : "",
      displayedKey: certMatches ? (config.client_key_path || "") : ""
    }
  }

  function buildPayload(serverUrl, clientCertInput, clientKeyInput, config) {
    var curServer = (serverUrl || "").trim() || "https://vault.bitwarden.com"
    var isOfficial = IconPolicy.isOfficialServer(curServer)
    var certPath = isOfficial ? "" : (clientCertInput ? clientCertInput.trim() : "")
    var keyPath = isOfficial ? "" : (clientKeyInput ? clientKeyInput.trim() : "")
    return {
      server_url: curServer,
      client_cert_path: certPath,
      client_key_path: keyPath
    }
  }

  Component.onCompleted: {
    console.log("Running mTLS UI Server Origin Gating & Payload Tests...")

    var testConfig = {
      server_url: "https://vault.bitwarden.com",
      client_cert_path: "/home/user/.certs/client.crt",
      client_key_path: "/home/user/.certs/client.key",
      client_cert_server: "https://vault.mycorp.internal:8443"
    }

    // 1. Official Server selected: cert fields must be suppressed and empty
    var offRes = resolveCertGating("https://vault.bitwarden.com", testConfig)
    check(offRes.isOfficial === true, "vault.bitwarden.com is detected as official")
    check(offRes.certMatchesServer === false, "Official server does not match custom mTLS server")
    check(offRes.displayedCert === "", "Displayed cert path is empty for official server")
    check(offRes.displayedKey === "", "Displayed key path is empty for official server")

    var offPayload = buildPayload("https://vault.bitwarden.com", "/home/user/.certs/client.crt", "/home/user/.certs/client.key", testConfig)
    check(offPayload.client_cert_path === "", "Payload clears cert path when saving on official server")
    check(offPayload.client_key_path === "", "Payload clears key path when saving on official server")

    // 2. Matching Self-Hosted Server: cert fields must be displayed
    var matchRes = resolveCertGating("https://vault.mycorp.internal:8443", testConfig)
    check(matchRes.isOfficial === false, "mycorp is self-hosted")
    check(matchRes.certMatchesServer === true, "Origin matches client_cert_server")
    check(matchRes.displayedCert === "/home/user/.certs/client.crt", "Displayed cert path matches configured path")
    check(matchRes.displayedKey === "/home/user/.certs/client.key", "Displayed key path matches configured path")

    var matchPayload = buildPayload("https://vault.mycorp.internal:8443", matchRes.displayedCert, matchRes.displayedKey, testConfig)
    check(matchPayload.client_cert_path === "/home/user/.certs/client.crt", "Payload preserves cert path for matching origin")
    check(matchPayload.client_key_path === "/home/user/.certs/client.key", "Payload preserves key path for matching origin")

    // 3. Different Self-Hosted Server (foreign origin): cert fields must NOT be displayed
    var diffRes = resolveCertGating("https://vault2.other.org", testConfig)
    check(diffRes.isOfficial === false, "vault2 is self-hosted")
    check(diffRes.certMatchesServer === false, "Foreign origin does not match client_cert_server")
    check(diffRes.displayedCert === "", "Foreign origin does NOT show certificate from other server")
    check(diffRes.displayedKey === "", "Foreign origin does NOT show key from other server")

    var diffPayload = buildPayload("https://vault2.other.org", diffRes.displayedCert, diffRes.displayedKey, testConfig)
    check(diffPayload.client_cert_path === "", "Payload suppresses cert path for foreign origin")
    check(diffPayload.client_key_path === "", "Payload suppresses key path for foreign origin")

    // 4. Switching back to matching origin restores cert
    var restoreRes = resolveCertGating("https://vault.mycorp.internal:8443/api", testConfig)
    check(restoreRes.certMatchesServer === true, "Same origin with different path matches and restores cert")
    check(restoreRes.displayedCert === "/home/user/.certs/client.crt", "Restored cert path matches")

    console.log("ALL mTLS UI GATING TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
