#!/usr/bin/env node
// VPN lifecycle and command dispatch.
"use strict";
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const state = require("./state");
const {
  validateRuntimeConfiguration,
  HTTP_PROXY_PORT,
  KEEPALIVE_STALE_MILLISECONDS,
  KEEPALIVE_TARGETS,
  LEAK_CHECK_INTERVAL_MILLISECONDS,
  LIVENESS_INTERVAL_MILLISECONDS,
  PROXY_SUPERVISE_INTERVAL_MILLISECONDS,
  PUBLIC_IP_FAMILY,
  PUBLIC_IP_ENDPOINT_POOL,
  RUNTIME_DIRECTORY,
  SOCKS_PROXY_PORT,
  TUNNEL_INTERFACE,
  VPN_SERVER,
  WATCHDOG_FAILURE_THRESHOLD,
  WATCHDOG_STARTUP_GRACE_MILLISECONDS,
} = require("./config");
const { log, isProcessRunning, streamProcessLines, waitForProcessExit, writeAtomicState } = require("./runtime");
const { readCredentials, generateTotp, safeLocation, runBrowser } = require("./authentication");
const {
  assertStaticResolverConfiguration,
  writeStaticResolverConfiguration,
  parseSplitTunnelDestinations,
  configureProxyKillSwitch,
  fetchPublicIp,
  captureOriginalPublicIp,
  readOriginalPublicIp,
  assertVpnPublicIp,
} = require("./network");
const {
  recordKeepaliveReply,
  startKeepalivePingers,
  stopKeepalivePingers,
  writeLivenessState,
  readLivenessState,
  tunnelLivenessFailureReason,
  tunnelLivenessFailureReasonFor,
  startupGraceApplies,
} = require("./keepalive");
const {
  probeHttpProxy,
  probeSocksProxy,
  superviseProxyProcesses,
  stopProxyProcesses,
} = require("./proxies");

function validateVpnServer() {
  if (!VPN_SERVER) {
    throw new Error("Environment is missing required field: VPN_SERVER");
  }
  const serverUrl = new URL(VPN_SERVER);
  if (serverUrl.protocol !== "https:") {
    throw new Error("VPN_SERVER must use HTTPS");
  }
  if (!["4", "6"].includes(PUBLIC_IP_FAMILY)) {
    throw new Error("VPN_PUBLIC_IP_FAMILY must be 4 or 6");
  }
}

function sanitizeOpenConnectLine(line) {
  if (/(cookie|token|session-id|x-dtls-session-id|sso-v2-login|samlrequest|\/api\/sso\/)/i
    .test(line)) {
    return "[authentication detail redacted]";
  }
  return line.replace(/https?:\/\/[^\s]+/g, (rawUrl) => safeLocation(rawUrl));
}

async function runWatchdogLeakCheck(watchdogState, openConnectProcess) {
  if (Date.now() - watchdogState.lastLeakCheckTimestamp < LEAK_CHECK_INTERVAL_MILLISECONDS
    && watchdogState.lastLeakCheckTimestamp > 0) return;
  watchdogState.lastLeakCheckTimestamp = Date.now();
  try {
    assertVpnPublicIp(await fetchPublicIp(), readOriginalPublicIp(), "direct");
    if (state.activeOpenConnectProcess !== openConnectProcess || state.reconnectRequested
      || state.shutdownRequested || tunnelLivenessFailureReason()) return;
    watchdogState.consecutiveLeakFailures = 0;
    state.tunnelReady = true;
  } catch (error) {
    log("warn", "watchdog.leak_check.failed", { error: error.message, inconclusive: !!error.inconclusive });
    if (!error.inconclusive) watchdogState.consecutiveLeakFailures += 1;
    if (error.leaked || watchdogState.consecutiveLeakFailures >= WATCHDOG_FAILURE_THRESHOLD) {
      state.reconnectRequested = true;
      state.tunnelReady = false;
    }
    watchdogState.lastLeakCheckTimestamp = Date.now() - LEAK_CHECK_INTERVAL_MILLISECONDS + 15000;
  }
}

async function runWatchdogProxySupervision(watchdogState) {
  if (Date.now() - watchdogState.lastProxySuperviseTimestamp < PROXY_SUPERVISE_INTERVAL_MILLISECONDS) return;
  watchdogState.lastProxySuperviseTimestamp = Date.now();
  await superviseProxyProcesses();
}

async function runWatchdogTick(openConnectProcess, watchdogState, startupDeadline) {
  const failure = tunnelLivenessFailureReason();
  writeLivenessState();
  const authenticationStatusPath = path.join(RUNTIME_DIRECTORY, "authentication-status");
  if (fs.existsSync(authenticationStatusPath)) {
    const status = JSON.parse(fs.readFileSync(authenticationStatusPath, "utf8"));
    if (status.session === watchdogState.session && status.failed) state.reconnectRequested = true;
  }
  const startupGrace = startupGraceApplies(watchdogState, startupDeadline,
    fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`));
  if (failure && startupGrace && !state.reconnectRequested) return false;
  if (failure) {
    watchdogState.consecutiveLivenessFailures += 1;
    log("warn", "watchdog.liveness.failed", { reason: failure,
      consecutiveFailures: watchdogState.consecutiveLivenessFailures });
  } else {
    watchdogState.tunnelWasObserved = true;
    watchdogState.consecutiveLivenessFailures = 0;
  }
  if (state.reconnectRequested || watchdogState.consecutiveLivenessFailures >= WATCHDOG_FAILURE_THRESHOLD) {
    state.reconnectRequested = true;
    state.tunnelReady = false;
    writeLivenessState();
    log("warn", "watchdog.reconnect.triggered", { reason: failure || "egress-check-failed" });
    openConnectProcess.kill("SIGTERM");
    await waitForProcessExit(openConnectProcess, 5000);
    return true;
  }
  if (!failure && !watchdogState.maintenance) {
    watchdogState.maintenance = runMaintenance(openConnectProcess, watchdogState)
      .catch(error => {
        log("error", "watchdog.maintenance.failed", { error: error.message });
        state.reconnectRequested = true;
      }).finally(() => { watchdogState.maintenance = null; });
  }
  return false;
}

async function runMaintenance(openConnectProcess, watchdogState) {
  await runWatchdogLeakCheck(watchdogState, openConnectProcess);
  if (state.activeOpenConnectProcess === openConnectProcess && state.tunnelReady
    && !state.reconnectRequested && !state.shutdownRequested) {
    await runWatchdogProxySupervision(watchdogState);
  }
}

async function monitorTunnel(openConnectProcess, session) {
  log("info", "watchdog.start", { failureThreshold: WATCHDOG_FAILURE_THRESHOLD,
    keepaliveStaleMilliseconds: KEEPALIVE_STALE_MILLISECONDS, keepaliveTargets: KEEPALIVE_TARGETS,
    livenessIntervalMilliseconds: LIVENESS_INTERVAL_MILLISECONDS });
  const startupDeadline = Date.now() + WATCHDOG_STARTUP_GRACE_MILLISECONDS;
  const watchdogState = { consecutiveLeakFailures: 0, consecutiveLivenessFailures: 0,
    lastLeakCheckTimestamp: 0, lastProxySuperviseTimestamp: 0, tunnelWasObserved: false,
    maintenance: null, session };
  while (!state.shutdownRequested && isProcessRunning(openConnectProcess)) {
    await new Promise(resolve => setTimeout(resolve, LIVENESS_INTERVAL_MILLISECONDS));
    if (state.shutdownRequested || !isProcessRunning(openConnectProcess)) break;
    if (await runWatchdogTick(openConnectProcess, watchdogState, startupDeadline)) break;
  }
  await watchdogState.maintenance;
  log("info", "watchdog.stop");
}

async function runOpenConnect() {
  log("info", "openconnect.start.enter", { server: safeLocation(VPN_SERVER) });
  state.tunnelReady = false;
  state.reconnectRequested = false;
  startKeepalivePingers();
  writeLivenessState();
  const session = crypto.randomUUID();
  const child = spawn("openconnect", ["--protocol=anyconnect",
    "--external-browser=/app/vpn.js", `--interface=${TUNNEL_INTERFACE}`,
    "--script=/app/vpnc-script", "--os=linux-64", "--useragent=AnyConnect Linux_64 5.1.11.388",
    "--version-string=5.1.11.388", "--timestamp", "--force-dpd=5", "--reconnect-timeout=300", VPN_SERVER],
  { env: { ...process.env, VPN_AUTHENTICATION_SESSION: session }, detached: true,
    stdio: ["ignore", "pipe", "pipe"] });
  state.activeOpenConnectProcess = child;
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  streamProcessLines(child.stdout, "openconnect", "stdout", sanitizeOpenConnectLine);
  streamProcessLines(child.stderr, "openconnect", "stderr", sanitizeOpenConnectLine);
  const monitoring = monitorTunnel(child, session).catch(error => {
    log("error", "watchdog.fatal", { error: error.message });
    process.exit(1);
  });
  let result;
  try { result = await exited; }
  finally {
    state.tunnelReady = false;
    state.reconnectRequested = true;
    state.activeOpenConnectProcess = null;
    stopKeepalivePingers();
    writeLivenessState();
    if (child.pid) {
      try { process.kill(-child.pid, "SIGKILL"); }
      catch (error) { if (error.code !== "ESRCH") throw error; }
    }
    await stopProxyProcesses("openconnect-exited");
    await monitoring;
  }
  log("warn", "openconnect.start.exit", result);
  if (result.signal === "SIGKILL") throw new Error("OpenConnect required forced termination; restarting container network");
  return result.code ?? 1;
}

async function connectForever() {
  validateRuntimeConfiguration();
  validateVpnServer();
  generateTotp(readCredentials().totpSecret);
  writeStaticResolverConfiguration();
  await configureProxyKillSwitch(false);
  writeLivenessState();
  while (!state.shutdownRequested) {
    try { await captureOriginalPublicIp(); break; }
    catch (error) {
      log("warn", "baseline.retry", { error: error.message });
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
  while (!state.shutdownRequested) {
    const exitCode = await runOpenConnect();
    if (state.shutdownRequested) break;
    await configureProxyKillSwitch(false);
    log("warn", "openconnect.restart.scheduled", { exitCode, delaySeconds: 5 });
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
}

async function runHealthcheck(emitSuccess = true) {
  const livenessFailureReason = tunnelLivenessFailureReasonFor(readLivenessState());
  if (livenessFailureReason) {
    throw new Error(livenessFailureReason);
  }
  readOriginalPublicIp();
  await Promise.all([probeHttpProxy(), probeSocksProxy()]);
  if (emitSuccess) {
    process.stdout.write(
      "healthy: tunnel keepalive is fresh and HTTP/SOCKS proxy listeners answer\n",
    );
  }
}

async function runDeepHealthcheck(emitSuccess = true) {
  await runHealthcheck(false);
  const originalPublicIp = readOriginalPublicIp();
  const [directPublicIp, httpPublicIp, socksPublicIp] = await Promise.all([
    fetchPublicIp(),
    fetchPublicIp(`http://127.0.0.1:${HTTP_PROXY_PORT}`, "HTTP proxy"),
    fetchPublicIp(`socks5h://127.0.0.1:${SOCKS_PROXY_PORT}`, "SOCKS5 proxy"),
  ]);
  assertVpnPublicIp(directPublicIp, originalPublicIp, "direct");
  assertVpnPublicIp(httpPublicIp, originalPublicIp, "HTTP proxy");
  assertVpnPublicIp(socksPublicIp, originalPublicIp, "SOCKS5 proxy");
  if (emitSuccess) {
    process.stdout.write(
      "healthy: VPN egress and HTTP/SOCKS proxy listeners are available\n",
    );
  }
}

async function runProbe() {
  log("info", "probe.start");
  while (true) {
    try {
      await runHealthcheck();
      log("info", "probe.healthy");
    } catch (error) {
      log("error", "probe.unhealthy", { error: error.message });
    }
    await new Promise((resolve) => setTimeout(resolve, 30000));
  }
}

async function runSelfTest() {
  const knownSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const knownCode = generateTotp(knownSecret, 59000, 8);
  if (knownCode !== "94287082") {
    throw new Error("RFC 6238 test vector failed");
  }
  const credentials = readCredentials();
  generateTotp(credentials.totpSecret);
  assertStaticResolverConfiguration();
  await fetchPublicIp();
  process.stdout.write(
    "self-test passed: credentials, RFC 6238 TOTP, static DNS, and curl verified\n",
  );
}

function installSignalHandlers() {
  ["SIGINT", "SIGTERM"].forEach(signalName => {
    process.once(signalName, () => {
      state.shutdownRequested = true;
      state.tunnelReady = false;
      log("warn", "shutdown.requested", { signal: signalName });
      stopKeepalivePingers();
      const child = state.activeOpenConnectProcess;
      if (isProcessRunning(child)) child.kill("SIGTERM");
      void Promise.all([stopProxyProcesses("shutdown-requested"),
        child ? waitForProcessExit(child, 5000) : Promise.resolve()])
        .catch(error => { log("error", "shutdown.failed", { error: error.message }); process.exit(1); });
    });
  });
}

async function main() {
  const command = process.argv[2] || "connect";
  if (/^https?:\/\//i.test(command)) {
    try { await runBrowser(command); }
    catch (error) {
      if (process.env.VPN_AUTHENTICATION_SESSION) writeAtomicState(
        path.join(RUNTIME_DIRECTORY, "authentication-status"), JSON.stringify({
          session: process.env.VPN_AUTHENTICATION_SESSION, failed: true,
        }));
      throw error;
    }
    return;
  }
  if (command === "connect") {
    installSignalHandlers();
    await connectForever();
    return;
  }
  if (command === "healthcheck") {
    await runHealthcheck();
    return;
  }
  if (command === "deep-healthcheck") {
    await runDeepHealthcheck();
    return;
  }
  if (command === "probe") {
    await runProbe();
    return;
  }
  if (command === "self-test") {
    await runSelfTest();
    return;
  }
  if (command === "configure-dns") {
    writeStaticResolverConfiguration();
    return;
  }
  if (command === "configure-kill-switch") {
    await configureProxyKillSwitch(!["pre-init", "disconnect"].includes(process.env.reason));
    return;
  }
  throw new Error(`Unknown command: ${command}`);
}

if (require.main === module) {
  main().catch((error) => {
    log("error", "fatal", { error: error.message });
    process.exit(1);
  });
}

module.exports = {
  KEEPALIVE_TARGETS,
  PUBLIC_IP_ENDPOINT_POOL,
  generateTotp,
  parseSplitTunnelDestinations,
  recordKeepaliveReply,
  tunnelLivenessFailureReason,
};
