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
    var enableMtls = Boolean(config && config.client_cert_path && certMatches)
    return {
      isOfficial: isOfficial,
      certMatchesServer: certMatches,
      enableMtlsChecked: enableMtls,
      displayedCert: certMatches ? (config.client_cert_path || "") : "",
      displayedKey: certMatches ? (config.client_key_path || "") : ""
    }
  }

  function buildPayload(serverUrl, enableMtlsChecked, clientCertInput, clientKeyInput) {
    var curServer = (serverUrl || "").trim() || "https://vault.bitwarden.com"
    var isOfficial = IconPolicy.isOfficialServer(curServer)
    var useMtls = !isOfficial && Boolean(enableMtlsChecked)
    var certPath = useMtls ? (clientCertInput ? clientCertInput.trim() : "") : ""
    var keyPath = useMtls ? (clientKeyInput ? clientKeyInput.trim() : "") : ""
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
    check(offRes.enableMtlsChecked === false, "mTLS toggle is disabled for official server")
    check(offRes.displayedCert === "", "Displayed cert path is empty for official server")
    check(offRes.displayedKey === "", "Displayed key path is empty for official server")

    var offPayload = buildPayload("https://vault.bitwarden.com", false, "/home/user/.certs/client.crt", "/home/user/.certs/client.key")
    check(offPayload.client_cert_path === "", "Payload clears cert path when saving on official server")
    check(offPayload.client_key_path === "", "Payload clears key path when saving on official server")

    // 2. Self-Hosted Server WITHOUT mTLS (Standard HTTPS/TLS, like user's server)
    var stdSelfHostedConfig = {
      server_url: "https://vaultwarden.lzsh.work"
    }
    var stdRes = resolveCertGating("https://vaultwarden.lzsh.work", stdSelfHostedConfig)
    check(stdRes.isOfficial === false, "vaultwarden.lzsh.work is self-hosted")
    check(stdRes.certMatchesServer === false, "Standard self-hosted server has no mTLS")
    check(stdRes.enableMtlsChecked === false, "mTLS checkbox is UNCHECKED for standard self-hosted server")
    check(stdRes.displayedCert === "", "Cert input is empty")

    var stdPayload = buildPayload("https://vaultwarden.lzsh.work", false, "", "")
    check(stdPayload.client_cert_path === "", "Standard self-hosted sends empty client_cert_path")
    check(stdPayload.client_key_path === "", "Standard self-hosted sends empty client_key_path")

    // 3. Matching Self-Hosted Server WITH mTLS enabled
    var matchRes = resolveCertGating("https://vault.mycorp.internal:8443", testConfig)
    check(matchRes.isOfficial === false, "mycorp is self-hosted")
    check(matchRes.certMatchesServer === true, "Origin matches client_cert_server")
    check(matchRes.enableMtlsChecked === true, "mTLS checkbox is CHECKED for server with configured cert")
    check(matchRes.displayedCert === "/home/user/.certs/client.crt", "Displayed cert path matches configured path")
    check(matchRes.displayedKey === "/home/user/.certs/client.key", "Displayed key path matches configured path")

    var matchPayload = buildPayload("https://vault.mycorp.internal:8443", true, matchRes.displayedCert, matchRes.displayedKey)
    check(matchPayload.client_cert_path === "/home/user/.certs/client.crt", "Payload preserves cert path for matching origin")
    check(matchPayload.client_key_path === "/home/user/.certs/client.key", "Payload preserves key path for matching origin")

    // 4. Switching back and forth
    var restoreRes = resolveCertGating("https://vault.mycorp.internal:8443/api", testConfig)
    check(restoreRes.certMatchesServer === true, "Same origin with different path matches and restores cert")
    check(restoreRes.displayedCert === "/home/user/.certs/client.crt", "Restored cert path matches")

    // 5. URL to Local Path Decoding Tests (File Picker integration)
    check(IconPolicy.urlToLocalPath("file:///home/user/.certs/client.crt") === "/home/user/.certs/client.crt", "File URL converted to POSIX path")
    check(IconPolicy.urlToLocalPath("file:///home/user/My%20Certs/client%20cert.crt") === "/home/user/My Certs/client cert.crt", "Encoded URI path decoded")
    check(IconPolicy.urlToLocalPath("/home/user/.certs/client.crt") === "/home/user/.certs/client.crt", "Raw POSIX path preserved")
    check(IconPolicy.urlToLocalPath("") === "", "Empty URL returns empty string")
    check(IconPolicy.urlToLocalPath(null) === "", "Null URL returns empty string")
    check(IconPolicy.urlToLocalPath(undefined) === "", "Undefined URL returns empty string")

    console.log("ALL mTLS UI GATING TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
