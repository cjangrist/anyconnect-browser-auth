// keepalive responsibilities for the VPN proxy.
"use strict";
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const state = require("./state");
const {
  KEEPALIVE_INTERVAL_SECONDS,
  KEEPALIVE_STALE_MILLISECONDS,
  KEEPALIVE_TARGETS,
  LIVENESS_STATE_FILE,
  LIVENESS_STATE_STALE_MILLISECONDS,
  TUNNEL_INTERFACE,
} = require("./config");
const { log, isProcessRunning, writeAtomicState } = require("./runtime");

function recordKeepaliveReply(outputLine) {
  if (/bytes from/i.test(outputLine)) {
    state.lastKeepaliveReplyTimestamp = Date.now();
  }
}

function startKeepalivePingerFor(target) {
  if (state.shutdownRequested || !fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)) return;
  const keepaliveProcess = spawn("ping", ["-n", "-I", TUNNEL_INTERFACE,
    "-c", "1", "-W", "2", "-w", "3", target], { stdio: ["ignore", "pipe", "pipe"] });
  state.activeKeepaliveProcesses.set(keepaliveProcess, target);
  let output = "";
  keepaliveProcess.stdout.on("data", chunk => { output += chunk; });
  keepaliveProcess.stderr.resume();
  keepaliveProcess.once("error", error => log("error", "keepalive.spawn.failed", { error: error.message }));
  keepaliveProcess.once("close", code => {
    if (state.activeKeepaliveProcesses.has(keepaliveProcess) && code === 0) recordKeepaliveReply(output);
    state.activeKeepaliveProcesses.delete(keepaliveProcess);
  });
}

function sendNextKeepalive() {
  const target = KEEPALIVE_TARGETS[state.keepaliveCursor % KEEPALIVE_TARGETS.length];
  state.keepaliveCursor += 1;
  startKeepalivePingerFor(target);
}

function startKeepalivePingers() {
  if (state.keepaliveTimer || state.shutdownRequested) return;
  state.lastKeepaliveReplyTimestamp = 0;
  log("info", "keepalive.start", { targets: KEEPALIVE_TARGETS, interface: TUNNEL_INTERFACE,
    intervalSeconds: KEEPALIVE_INTERVAL_SECONDS });
  sendNextKeepalive();
  state.keepaliveTimer = setInterval(sendNextKeepalive, KEEPALIVE_INTERVAL_SECONDS * 1000);
}

function stopKeepalivePingers() {
  clearInterval(state.keepaliveTimer);
  state.keepaliveTimer = null;
  [...state.activeKeepaliveProcesses.keys()].filter(isProcessRunning)
    .forEach(keepaliveProcess => keepaliveProcess.kill("SIGKILL"));
  state.activeKeepaliveProcesses.clear();
  state.lastKeepaliveReplyTimestamp = 0;
}

function writeLivenessState() {
  const livenessState = JSON.stringify({
    keepaliveTargets: KEEPALIVE_TARGETS,
    lastKeepaliveReplyTimestamp: state.lastKeepaliveReplyTimestamp,
    ready: state.tunnelReady && !state.reconnectRequested && !state.shutdownRequested,
    observedAt: Date.now(),
    tunnelInterface: TUNNEL_INTERFACE,
  });
  writeAtomicState(LIVENESS_STATE_FILE, `${livenessState}\n`);
}

function readLivenessState() {
  if (!fs.existsSync(LIVENESS_STATE_FILE)) {
    throw new Error("Tunnel liveness state has not been published yet");
  }
  const livenessState = JSON.parse(fs.readFileSync(LIVENESS_STATE_FILE, "utf8"));
  const stateAgeMilliseconds = Date.now() - Number(livenessState.observedAt);
  if (!Number.isFinite(stateAgeMilliseconds)
    || stateAgeMilliseconds < 0
    || stateAgeMilliseconds > LIVENESS_STATE_STALE_MILLISECONDS) {
    throw new Error(`Tunnel liveness state is stale by ${stateAgeMilliseconds}ms`);
  }
  return livenessState;
}

function livenessFailureReason(tunnelInterface, keepaliveTarget, lastReplyTimestamp) {
  if (!fs.existsSync(`/sys/class/net/${tunnelInterface}`)) {
    return `tunnel interface ${tunnelInterface} is absent`;
  }
  const interfaceFlags = Number(fs.readFileSync(`/sys/class/net/${tunnelInterface}/flags`, "utf8"));
  if (!(interfaceFlags & 1)) return `tunnel interface ${tunnelInterface} is down`;
  const millisecondsSinceReply = Date.now() - lastReplyTimestamp;
  if (!Number.isFinite(millisecondsSinceReply) || millisecondsSinceReply < 0
    || millisecondsSinceReply > KEEPALIVE_STALE_MILLISECONDS) {
    return `no ${keepaliveTarget} keepalive reply for ${millisecondsSinceReply}ms`;
  }
  return "";
}

function tunnelLivenessFailureReason() {
  return livenessFailureReason(
    TUNNEL_INTERFACE,
    KEEPALIVE_TARGETS.join(", "),
    state.lastKeepaliveReplyTimestamp,
  );
}

function startupGraceApplies(watchdogState, startupDeadline, interfacePresent, now = Date.now()) {
  if (interfacePresent && !watchdogState.interfaceObservedAt) watchdogState.interfaceObservedAt = now;
  if (watchdogState.tunnelWasObserved) return false;
  return now < Math.min(startupDeadline, watchdogState.interfaceObservedAt
    ? watchdogState.interfaceObservedAt + KEEPALIVE_STALE_MILLISECONDS : startupDeadline);
}

function tunnelLivenessFailureReasonFor(livenessState) {
  if (!livenessState.ready) return "VPN is not ready to serve traffic";
  return livenessFailureReason(
    livenessState.tunnelInterface || TUNNEL_INTERFACE,
    (livenessState.keepaliveTargets || KEEPALIVE_TARGETS).join(", "),
    Number(livenessState.lastKeepaliveReplyTimestamp) || 0,
  );
}

module.exports = {
  startupGraceApplies,
  recordKeepaliveReply,
  sendNextKeepalive,
  startKeepalivePingerFor,
  startKeepalivePingers,
  stopKeepalivePingers,
  writeLivenessState,
  readLivenessState,
  livenessFailureReason,
  tunnelLivenessFailureReason,
  tunnelLivenessFailureReasonFor,
};
