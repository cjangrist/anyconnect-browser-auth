// Supervisor-owned child processes and liveness state.
"use strict";
const crypto = require("node:crypto");
const { PUBLIC_IP_ENDPOINTS } = require("./config");
const activeKeepaliveProcesses = new Map();
let activeOpenConnectProcess = null;
const activeProxyProcesses = new Map();
let lastKeepaliveReplyTimestamp = 0;
let publicIpEndpointCursor = crypto.randomInt(PUBLIC_IP_ENDPOINTS.length);
const proxyConsecutiveFailureCounts = new Map();
const proxyLastEgressCheckTimestamps = new Map();
let proxyOperationPromise = Promise.resolve();
let playwrightErrors = null;
let shutdownRequested = false;
let socksProxyGroupId = null;
let socksProxyUserId = null;


module.exports = { tunnelReady: false, reconnectRequested: false, keepaliveTimer: null, keepaliveCursor: 0, activeKeepaliveProcesses, activeOpenConnectProcess, activeProxyProcesses, lastKeepaliveReplyTimestamp, publicIpEndpointCursor, proxyConsecutiveFailureCounts, proxyLastEgressCheckTimestamps, proxyOperationPromise, playwrightErrors, shutdownRequested, socksProxyGroupId, socksProxyUserId };
