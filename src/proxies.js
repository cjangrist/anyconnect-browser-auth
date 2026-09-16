// proxies responsibilities for the VPN proxy.
"use strict";
const net = require("node:net");
const { spawn } = require("node:child_process");
const state = require("./state");
const {
  HTTP_PROXY_PORT,
  PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS,
  PROXY_FAILURE_THRESHOLD,
  PROXY_LISTEN_ADDRESS,
  PROXY_PROBE_TIMEOUT_MILLISECONDS,
  PROXY_START_TIMEOUT_MILLISECONDS,
  SOCKS_PROXY_PORT,
} = require("./config");
const { log, isProcessRunning, streamProcessLines, waitForProcessExit } = require("./runtime");

const { fetchPublicIp, readOriginalPublicIp, assertVpnPublicIp } = require("./network");

function probeProxyProtocol(port, requestBytes, responseIsValid, protocolName) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const responseChunks = [];
    let settled = false;
    const finish = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      socket.destroy();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const deadline = setTimeout(() => finish(new Error(`${protocolName} proxy probe timed out`)),
      PROXY_PROBE_TIMEOUT_MILLISECONDS);
    socket.once("connect", () => socket.write(requestBytes));
    socket.on("data", (chunk) => {
      responseChunks.push(chunk);
      if (responseIsValid(Buffer.concat(responseChunks))) {
        finish();
      }
    });
    socket.once("error", (error) => {
      finish(new Error(`${protocolName} proxy probe failed: ${error.message}`));
    });
    socket.once("timeout", () => {
      finish(new Error(`${protocolName} proxy probe timed out`));
    });
    socket.once("close", () => {
      finish(new Error(`${protocolName} proxy returned an invalid response`));
    });
  });
}

function probeHttpProxy() {
  const requestBytes = Buffer.from(
    "GET http://tinyproxy.health/ HTTP/1.1\r\n"
      + "Host: tinyproxy.health\r\n"
      + "Connection: close\r\n\r\n",
  );
  return probeProxyProtocol(
    HTTP_PROXY_PORT,
    requestBytes,
    (response) => /^HTTP\/1\.[01] 200\b/.test(response.toString("utf8")),
    "HTTP",
  );
}

function probeSocksProxy() {
  return probeProxyProtocol(
    SOCKS_PROXY_PORT,
    Buffer.from([0x05, 0x01, 0x00]),
    (response) => response.length >= 2 && response[0] === 0x05 && response[1] === 0x00,
    "SOCKS5",
  );
}

async function waitForProxyProbe(probe, port) {
  const deadline = Date.now() + PROXY_START_TIMEOUT_MILLISECONDS;
  let lastError = new Error("Proxy probe was not attempted");
  while (Date.now() < deadline) {
    try {
      await probe();
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Proxy on port ${port} did not become ready: ${lastError.message}`);
}

function proxyDefinitions() {
  if (!Number.isSafeInteger(state.socksProxyGroupId) || !Number.isSafeInteger(state.socksProxyUserId)) {
    throw new Error("SOCKS proxy user and group IDs are not configured");
  }
  return [
    {
      arguments: ["-d", "-c", "/etc/tinyproxy/tinyproxy.conf"],
      command: "tinyproxy",
      egressProxyUrl: `http://127.0.0.1:${HTTP_PROXY_PORT}`,
      name: "http_proxy",
      port: HTTP_PROXY_PORT,
      probe: probeHttpProxy,
    },
    {
      arguments: ["-i", PROXY_LISTEN_ADDRESS, "-p", String(SOCKS_PROXY_PORT)],
      command: "microsocks",
      egressProxyUrl: `socks5h://127.0.0.1:${SOCKS_PROXY_PORT}`,
      gid: state.socksProxyGroupId,
      name: "socks_proxy",
      port: SOCKS_PROXY_PORT,
      probe: probeSocksProxy,
      uid: state.socksProxyUserId,
    },
  ];
}

function queueProxyOperation(operation) {
  const queuedOperation = state.proxyOperationPromise.then(operation, operation);
  state.proxyOperationPromise = queuedOperation.catch(() => {});
  return queuedOperation;
}

function canServeProxyTraffic() {
  return state.tunnelReady && !state.reconnectRequested && !state.shutdownRequested
    && Boolean(state.activeOpenConnectProcess)
    && isProcessRunning(state.activeOpenConnectProcess);
}

function startProxyProcess(definition) {
  log("info", `${definition.name}.start.enter`, {
    address: PROXY_LISTEN_ADDRESS,
    port: definition.port,
  });
  const proxyProcess = spawn(definition.command, definition.arguments, {
    gid: definition.gid,
    stdio: ["ignore", "pipe", "pipe"],
    uid: definition.uid,
  });
  state.activeProxyProcesses.set(definition.name, proxyProcess);
  streamProcessLines(proxyProcess.stdout, definition.name, "stdout");
  streamProcessLines(proxyProcess.stderr, definition.name, "stderr");
  proxyProcess.once("error", (error) => {
    if (state.activeProxyProcesses.get(definition.name) === proxyProcess) {
      state.activeProxyProcesses.delete(definition.name);
    }
    log("error", `${definition.name}.start.error`, { error: error.message });
  });
  proxyProcess.once("exit", (code, signal) => {
    if (state.activeProxyProcesses.get(definition.name) === proxyProcess) {
      state.activeProxyProcesses.delete(definition.name);
    }
    log("warn", `${definition.name}.start.exit`, { code, signal });
  });
}

async function startProxyAndWaitForReadiness(definition) {
  if (!canServeProxyTraffic()) return;
  startProxyProcess(definition);
  await waitForProxyProbe(definition.probe, definition.port);
  state.proxyConsecutiveFailureCounts.set(definition.name, 0);
  state.proxyLastEgressCheckTimestamps.set(definition.name, Date.now());
  log("info", `${definition.name}.ready`, { port: definition.port });
}

async function restartProxyProcess(definition, reason) {
  log("warn", `${definition.name}.restart.enter`, { reason });
  const previousProcess = state.activeProxyProcesses.get(definition.name);
  if (previousProcess) {
    if (isProcessRunning(previousProcess)) {
      previousProcess.kill("SIGTERM");
    }
    await waitForProcessExit(previousProcess, 5000);
    if (state.activeProxyProcesses.get(definition.name) === previousProcess) {
      state.activeProxyProcesses.delete(definition.name);
    }
  }
  await startProxyAndWaitForReadiness(definition);
  log("warn", `${definition.name}.restart.exit`, { reason });
}

function proxyEgressCheckIsDue(definitionName) {
  const lastCheckTimestamp = state.proxyLastEgressCheckTimestamps.get(definitionName) || 0;
  return Date.now() - lastCheckTimestamp >= PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS;
}

async function verifyProxyEgress(definition) {
  const originalPublicIp = readOriginalPublicIp();
  state.proxyLastEgressCheckTimestamps.set(definition.name, Date.now());
  const proxyPublicIp = await fetchPublicIp(definition.egressProxyUrl, definition.name);
  assertVpnPublicIp(proxyPublicIp, originalPublicIp, definition.name);
  state.proxyLastEgressCheckTimestamps.set(definition.name, Date.now());
}

async function superviseProxy(definition) {
  if (!state.activeProxyProcesses.has(definition.name)) {
    await startProxyAndWaitForReadiness(definition);
    return;
  }
  await definition.probe();
  if (proxyEgressCheckIsDue(definition.name)) {
    await verifyProxyEgress(definition);
  }
  state.proxyConsecutiveFailureCounts.set(definition.name, 0);
}

async function superviseProxyTolerantly(definition) {
  try {
    await superviseProxy(definition);
  } catch (error) {
    if (error.leaked) {
      log("error", `${definition.name}.egress.leaked`, { error: error.message });
      state.reconnectRequested = true;
      state.tunnelReady = false;
      return;
    }
    if (error.inconclusive) {
      state.proxyLastEgressCheckTimestamps.set(definition.name, Date.now());
      log("debug", `${definition.name}.check.inconclusive`, { error: error.message });
      return;
    }
    const consecutiveFailures = (state.proxyConsecutiveFailureCounts.get(definition.name) || 0) + 1;
    state.proxyLastEgressCheckTimestamps.set(definition.name, 0);
    state.proxyConsecutiveFailureCounts.set(definition.name, consecutiveFailures);
    log("warn", `${definition.name}.check.failed`, {
      consecutiveFailures,
      error: error.message,
    });
    if (consecutiveFailures < PROXY_FAILURE_THRESHOLD) {
      return;
    }
    state.proxyConsecutiveFailureCounts.set(definition.name, 0);
    await restartProxyProcess(definition, "health-threshold-exceeded");
  }
}

async function superviseProxyProcesses() {
  await queueProxyOperation(async () => {
    if (!canServeProxyTraffic()) {
      log("warn", "proxies.supervise.skipped", { reason: "openconnect-not-running" });
      return;
    }
    const results = await Promise.allSettled(proxyDefinitions().map(
      (definition) => superviseProxyTolerantly(definition),
    ));
    const failures = results.filter(result => result.status === "rejected");
    if (failures.length) throw new AggregateError(failures.map(result => result.reason),
      "Proxy supervision could not safely finish");
  });
}

async function stopProxyProcesses(reason) {
  await queueProxyOperation(async () => {
    state.proxyConsecutiveFailureCounts.clear();
    state.proxyLastEgressCheckTimestamps.clear();
    const proxyProcesses = [...state.activeProxyProcesses.values()];
    if (!proxyProcesses.length) {
      return;
    }
    log("warn", "proxies.stop.enter", { reason });
    proxyProcesses
      .filter(isProcessRunning)
      .forEach((proxyProcess) => proxyProcess.kill("SIGTERM"));
    await Promise.all(proxyProcesses.map(
      (proxyProcess) => waitForProcessExit(proxyProcess, 5000),
    ));
    log("warn", "proxies.stop.exit", { reason });
  });
}

module.exports = {
  probeProxyProtocol,
  probeHttpProxy,
  probeSocksProxy,
  waitForProxyProbe,
  proxyDefinitions,
  queueProxyOperation,
  canServeProxyTraffic,
  startProxyProcess,
  startProxyAndWaitForReadiness,
  restartProxyProcess,
  proxyEgressCheckIsDue,
  verifyProxyEgress,
  superviseProxy,
  superviseProxyTolerantly,
  superviseProxyProcesses,
  stopProxyProcesses,
};
