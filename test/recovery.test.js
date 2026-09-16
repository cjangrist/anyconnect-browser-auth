// Exercise real subprocess, socket, firewall policy, and IP-provider failure behavior.
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { runCommand, waitForProcessExit, writeAtomicState } = require("../src/runtime");
const { fetchPublicIp, fetchPublicIpFromEndpoint, firewallRestoreRules,
  parsePushedExclusions, assertVpnPublicIp, nextPublicIpEndpoint } = require("../src/network");
const { probeProxyProtocol } = require("../src/proxies");
const { livenessFailureReason } = require("../src/keepalive");
const { KEEPALIVE_TARGETS, KEEPALIVE_INTERVAL_SECONDS } = require("../src/config");

async function startHttpFixture(context, responder) {
  const server = http.createServer(responder);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test("a dead IP provider falls back to a different real endpoint", async context => {
  let failedRequests = 0;
  const bad = await startHttpFixture(context, (request, response) => {
    failedRequests += 1;
    response.writeHead(503).end("unavailable");
  });
  const good = await startHttpFixture(context, (request, response) => response.end("203.0.113.9"));
  const endpoints = [bad, good];
  while (nextPublicIpEndpoint(endpoints) !== good) {}
  assert.equal(await fetchPublicIp("", "fixture", endpoints), "203.0.113.9");
  assert.equal(failedRequests, 1);
});

test("all HTTP provider failures remain inconclusive", async context => {
  const endpoint = await startHttpFixture(context, (request, response) => response.writeHead(429).end());
  await assert.rejects(fetchPublicIp("", "fixture", [endpoint]), error => error.inconclusive === true);
});

test("all transport failures remain distinguishable from website errors", async context => {
  const endpoint = await startHttpFixture(context, (request, response) => response.destroy());
  await assert.rejects(fetchPublicIp("", "fixture", [endpoint]), error => error.inconclusive === false);
});

test("HTML cannot be accepted as a public IP", async context => {
  const endpoint = await startHttpFixture(context, (request, response) => response.end("<html>maintenance</html>"));
  await assert.rejects(fetchPublicIpFromEndpoint(endpoint), error => error.inconclusive === true);
});

test("a confirmed direct egress leak is separately identified", () => {
  assert.throws(() => assertVpnPublicIp("203.0.113.9", "203.0.113.9", "fixture"),
    error => error.leaked === true);
});

test("firewall refresh replaces its chain in one transaction", () => {
  const rules = firewallRestoreRules([{ userId: 101, listenPort: 8080 },
    { userId: 65534, listenPort: 1080 }], ["40.96.0.0/13"], "tun0");
  assert.equal(rules.split("COMMIT").length, 2);
  assert.match(rules, /^\*filter\n:VPN_PROXY_KILLSWITCH - \[0:0\]\n/);
  assert.equal((rules.match(/-j REJECT/g) || []).length, 2);
  assert.match(rules, /--uid-owner 101 ! -o tun0 -d 40\.96\.0\.0\/13 -j ACCEPT/);
  assert.doesNotMatch(rules, /:OUTPUT|:INPUT|:FORWARD/);
});

test("only explicitly pushed exclusions become bypass prefixes", () => {
  assert.deepEqual(parsePushedExclusions({ CISCO_SPLIT_EXC: "1",
    CISCO_SPLIT_EXC_0_ADDR: "40.96.0.0", CISCO_SPLIT_EXC_0_MASKLEN: "13" }, 4), ["40.96.0.0/13"]);
  assert.deepEqual(parsePushedExclusions({}, 4), []);
  assert.throws(() => parsePushedExclusions({ CISCO_SPLIT_EXC: "1",
    CISCO_SPLIT_EXC_0_ADDR: "0.0.0.0", CISCO_SPLIT_EXC_0_MASKLEN: "0" }, 4));
  assert.throws(() => parsePushedExclusions({ CISCO_SPLIT_EXC: "NaN" }, 4));
});

test("keepalives rotate at one packet per second across independent networks", () => {
  assert.equal(KEEPALIVE_INTERVAL_SECONDS, 1);
  assert.ok(KEEPALIVE_TARGETS.length >= 5);
  assert.equal(new Set(KEEPALIVE_TARGETS).size, KEEPALIVE_TARGETS.length);
  KEEPALIVE_TARGETS.forEach(target => assert.ok(net.isIP(target)));
});

test("missing and invalid reply timestamps cannot report healthy", () => {
  assert.match(livenessFailureReason("lo", "fixture", NaN), /no fixture keepalive reply/);
  assert.match(livenessFailureReason("lo", "fixture", Date.now() + 60000), /no fixture keepalive reply/);
});

test("a stopped subprocess is killed within the cleanup deadline", async () => {
  const child = spawn("sleep", ["60"]);
  await once(child, "spawn");
  child.kill("SIGSTOP");
  const stopDeadline = Date.now() + 2000;
  while (!/^State:\s+T/m.test(fs.readFileSync(`/proc/${child.pid}/status`, "utf8"))) {
    assert.ok(Date.now() < stopDeadline, "Fixture did not enter stopped state");
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  child.kill("SIGTERM");
  const started = Date.now();
  await waitForProcessExit(child, 100);
  assert.equal(child.signalCode, "SIGKILL");
  assert.ok(Date.now() - started < 2000);
});

test("waiting for a previously exited child returns promptly", async () => {
  const child = spawn("true");
  await once(child, "exit");
  await waitForProcessExit(child, 100);
});

test("command execution has an absolute deadline", async () => {
  await assert.rejects(runCommand("sleep", ["60"], "", 100), /exceeded 100ms/);
});

test("a command spawn failure rejects instead of hanging", async () => {
  await assert.rejects(runCommand("/nonexistent/vpn-test-command", []), /ENOENT/);
});

test("protocol probes accept fragmented real responses", async context => {
  const server = net.createServer(socket => {
    socket.once("data", () => {
      socket.write(Buffer.from([5]));
      setTimeout(() => socket.end(Buffer.from([0])), 20);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => new Promise(resolve => server.close(resolve)));
  await probeProxyProtocol(server.address().port, Buffer.from([5, 1, 0]),
    response => response.length === 2 && response[0] === 5 && response[1] === 0, "fixture");
});

test("liveness publication leaves no partially written JSON", () => {
  const directory = path.join("tmp", "20260913_unit_state", String(process.pid));
  const filename = path.join(directory, "liveness");
  Array.from({ length: 30 }, (_, observedAt) => {
    writeAtomicState(filename, JSON.stringify({ observedAt, ready: true }));
    assert.deepEqual(JSON.parse(fs.readFileSync(filename, "utf8")), { observedAt, ready: true });
  });
  assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  const archive = path.join("trash", "20260913_unit_state");
  fs.mkdirSync(archive, { recursive: true });
  fs.renameSync(directory, path.join(archive, String(process.pid)));
});

test("configured tunnel without replies loses startup grace after fifteen seconds", () => {
  const { startupGraceApplies } = require("../src/keepalive");
  const state = { tunnelWasObserved: false };
  assert.equal(startupGraceApplies(state, 210000, false, 1000), true);
  assert.equal(startupGraceApplies(state, 210000, true, 5000), true);
  assert.equal(startupGraceApplies(state, 210000, true, 19999), true);
  assert.equal(startupGraceApplies(state, 210000, true, 20000), false);
  assert.equal(startupGraceApplies(state, 210000, false, 20001), false);
  state.tunnelWasObserved = true;
  assert.equal(startupGraceApplies(state, 210000, true, 10000), false);
});

test("visible unfocused password takes precedence over stale username", async () => {
  const { handleCredentialForm } = require("../src/authentication");
  let supplied = "";
  let submitted = false;
  const page = {
    locator(selector) {
      assert.ok(selector.includes("passwd"), `Unexpected selector: ${selector}`);
      return { first: () => ({ count: async () => 1, isVisible: async () => true,
        fill: async value => { supplied = value; }, inputValue: async () => supplied,
        press: async key => { assert.equal(key, "Enter"); submitted = true; } }) };
    },
    waitForTimeout: async () => {},
  };
  const state = { lastAction: "account-picker" };
  assert.equal(await handleCredentialForm(page, { password: "fixture-password" }, state), true);
  assert.equal(supplied, "fixture-password");
  assert.equal(submitted, true);
  assert.equal(state.lastAction, "password");
});

test("invisible password decoy cannot replace username submission", async () => {
  const { handleCredentialForm } = require("../src/authentication");
  let supplied = "";
  const page = {
    locator(selector) {
      const decoy = selector.includes("passwd") || selector.includes('type="password"');
      if (decoy) assert.match(selector, /:not\(\[aria-hidden="true"\]\)/);
      return { first: () => ({ count: async () => decoy ? 0 : 1,
        isVisible: async () => true, fill: async value => { supplied = value; },
        inputValue: async () => supplied, click: async () => {} }) };
    },
    waitForTimeout: async () => {},
  };
  const state = { lastAction: "none" };
  assert.equal(await handleCredentialForm(page, { username: "fixture-user" }, state), true);
  assert.equal(supplied, "fixture-user");
  assert.equal(state.lastAction, "username");
});

test("HTTP CONNECT rejection is a proxy transport failure, not an endpoint outage", async context => {
  const server = http.createServer();
  server.on('connect', (request, socket) => socket.end('HTTP/1.1 500 Unable to connect\r\nContent-Length: 0\r\n\r\n'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  context.after(() => new Promise(resolve => server.close(resolve)));
  const proxy = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(fetchPublicIpFromEndpoint('https://unreachable.invalid/', proxy),
    error => error.inconclusive === false);
});
