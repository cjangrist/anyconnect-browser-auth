#!/usr/bin/env node
// Opt-in local fault injection: verify recovery through real proxies and Chrome.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify, parseArgs } = require("node:util");
const execute = promisify(execFile);
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function command(binary, argumentsList, allowFailure = false) {
  try {
    return await execute(binary, argumentsList, { timeout: 45000, maxBuffer: 16 * 1024 * 1024 });
  } catch (error) {
    if (allowFailure) return { stdout: error.stdout || "", stderr: error.stderr || "", code: error.code };
    throw error;
  }
}

async function containerCommand(container, ...argumentsList) {
  return command("docker", ["exec", container, ...argumentsList]);
}

async function pid(container, name) {
  const result = await command("docker", ["exec", container, "pgrep", "-x", name], true);
  return result.stdout.trim();
}

async function request(proxy, url = "https://example.com/") {
  const timingFormat = '{"status":"%{http_code}","connect":%{time_connect},"tls":%{time_appconnect},"total":%{time_total}}';
  const result = await command("curl", ["--noproxy", "", "--proxy", proxy, "--silent",
    "--show-error", "--verbose", "--trace-time", "--max-time", "12", "--output", "/dev/null", "--write-out", timingFormat, url], true);
  const timing = JSON.parse(result.stdout || "{}");
  return { code: result.code || 0, status: Number(timing.status), proxy, url, timing,
    ...(result.code ? { diagnostic: result.stderr } : {}) };
}

async function requireRequest(proxy, url) {
  const result = await request(proxy, url);
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.ok(result.status >= 200 && result.status < 400, JSON.stringify(result));
}

async function browserProof(configuration, protocol, url = "https://example.com/") {
  const navigationUrl = new URL(url);
  navigationUrl.searchParams.set("vpn_recovery_check", String(Date.now()));
  const session = `${configuration.session}-${protocol}`;
  const proxy = protocol === "http" ? "http://127.0.0.1:8080" : "socks5://127.0.0.1:1080";
  const argumentsList = ["--config", configuration.browserConfig, "--session", session,
    "--args", "--no-sandbox", "--proxy", proxy, "--json"];
  const navigation = JSON.parse((await command("agent-browser", [...argumentsList, "open", navigationUrl.href])).stdout);
  assert.equal(navigation.success, true, JSON.stringify(navigation));
  const evaluated = JSON.parse((await command("agent-browser", [...argumentsList, "eval",
    "({url:location.href,title:document.title,text:document.body.innerText})"])).stdout);
  assert.equal(evaluated.success, true, JSON.stringify(evaluated));
  const result = evaluated.data.result;
  assert.ok(result.url.startsWith("https://"));
  assert.doesNotMatch(result.text, /ERR_|No response from server|site can.t be reached|Check your internet/i);
  assert.ok(result.text.length > 60, JSON.stringify(result));
  return { protocol, url: result.url, title: result.title, characters: result.text.length };
}

async function browserCleanup(configuration) {
  const results = [];
  for (const protocol of ["http", "socks"]) {
    const argumentsList = ["--config", configuration.browserConfig, "--session", `${configuration.session}-${protocol}`, "--json"];
    const result = JSON.parse((await command("agent-browser", [...argumentsList, "tab", "list"])).stdout);
    assert.equal(result.success, true, JSON.stringify(result));
    const tabs = result.data.tabs;
    await command("agent-browser", [...argumentsList, "tab", "new", "about:blank"]);
    for (const tab of tabs) await command("agent-browser", [...argumentsList, "tab", "close", String(tab.tabId)]);
    const remaining = JSON.parse((await command("agent-browser", [...argumentsList, "tab", "list"])).stdout);
    assert.equal(remaining.success, true, JSON.stringify(remaining));
    assert.equal(remaining.data.tabs.length, 1, JSON.stringify(remaining));
    assert.equal(remaining.data.tabs[0].url, "about:blank", JSON.stringify(remaining));
    results.push({ protocol, tabs: remaining.data.tabs });
  }
  return results;
}

async function waitHealthy(configuration, milliseconds = 180000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const result = await command("docker", ["exec", configuration.container, "/app/vpn.js", "healthcheck"], true);
    if (!result.code) return;
    await sleep(2000);
  }
  throw new Error("VPN did not recover within the deadline");
}

async function proxyFault(configuration, target, signal) {
  const container = configuration.container;
  const sibling = target === "tinyproxy" ? "microsocks" : "tinyproxy";
  const siblingProxy = sibling === "microsocks" ? "socks5h://127.0.0.1:1080" : "http://127.0.0.1:8080";
  const original = await pid(container, target);
  const originalSibling = await pid(container, sibling);
  const started = Date.now();
  await containerCommand(container, "pkill", `-${signal}`, "-x", target);
  let recovered = false;
  let maximumStateAge = 0;
  while (Date.now() - started < 100000) {
    await requireRequest(siblingProxy);
    const state = JSON.parse((await containerCommand(container, "cat", "/run/vpn-sidecar/liveness")).stdout);
    maximumStateAge = Math.max(maximumStateAge, Date.now() - state.observedAt);
    const current = await pid(container, target);
    if (current && current !== original) { recovered = true; break; }
    await sleep(1500);
  }
  assert.ok(recovered, `${target} failed to recover`);
  assert.equal(await pid(container, sibling), originalSibling);
  assert.ok(maximumStateAge < 3000, `liveness delayed by ${maximumStateAge}ms`);
  await waitHealthy(configuration);
  const browser = await browserProof(configuration, target === "tinyproxy" ? "http" : "socks");
  return { target, signal, recoveryMilliseconds: Date.now() - started, maximumStateAge, browser };
}

async function keepaliveRedundancy(configuration) {
  const container = configuration.container;
  const original = await pid(container, "openconnect");
  const rule = ["OUTPUT", "-o", "tun0", "-p", "icmp", "-d", "1.1.1.1", "-j", "DROP"];
  await containerCommand(container, "iptables", "-I", ...rule);
  try {
    const deadline = Date.now() + 22000;
    while (Date.now() < deadline) {
      await requireRequest("http://127.0.0.1:8080");
      await sleep(2000);
    }
    assert.equal(await pid(container, "openconnect"), original);
    await waitHealthy(configuration);
    return { blockedTarget: "1.1.1.1", noReconnect: true, browser: await browserProof(configuration, "http") };
  } finally { await containerCommand(container, "iptables", "-D", ...rule); }
}

async function tunnelFault(configuration, mode) {
  const container = configuration.container;
  const original = await pid(container, "openconnect");
  const started = Date.now();
  const rule = ["OUTPUT", "-o", "tun0", "-p", "icmp", "-j", "DROP"];
  if (mode === "icmp") await containerCommand(container, "iptables", "-I", ...rule);
  if (mode === "down") await containerCommand(container, "ip", "link", "set", "tun0", "down");
  if (mode === "term") await containerCommand(container, "pkill", "-TERM", "-x", "openconnect");
  if (mode === "stop") await containerCommand(container, "pkill", "-STOP", "-x", "openconnect");
  let changed = false;
  try {
    while (Date.now() - started < 70000) {
      const current = await pid(container, "openconnect");
      if (current !== original) { changed = true; break; }
      await sleep(500);
    }
    assert.ok(changed, `OpenConnect did not react to ${mode}`);
  } finally {
    if (mode === "icmp") await containerCommand(container, "iptables", "-D", ...rule);
  }
  const detectionMilliseconds = Date.now() - started;
  await waitHealthy(configuration);
  await containerCommand(container, "/app/vpn.js", "deep-healthcheck");
  const browser = await browserProof(configuration, "http");
  const socksBrowser = await browserProof(configuration, "socks");
  return { mode, detectionMilliseconds, recoveryMilliseconds: Date.now() - started, browser, socksBrowser };
}

async function keepaliveCadence(configuration) {
  const container = configuration.container;
  const rule = ["OUTPUT", "-o", "tun0", "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"];
  await containerCommand(container, "iptables", "-I", ...rule);
  try {
    await sleep(12000);
    const result = await containerCommand(container, "iptables", "-L", "OUTPUT", "-n", "-v", "-x", "--line-numbers");
    const line = result.stdout.split("\n").find(line => /^1\s/.test(line));
    const packets = Number(line.trim().split(/\s+/)[1]);
    assert.ok(packets >= 11 && packets <= 13, `Expected one echo per second, observed ${packets}/12s`);
    return { packets, windowSeconds: 12, browser: await browserProof(configuration, "socks") };
  } finally { await containerCommand(container, "iptables", "-D", ...rule); }
}

async function saturation(configuration) {
  const holders = Array.from({ length: 150 }, () => net.createConnection({ host: "127.0.0.1", port: 8080 }));
  try {
    await Promise.all(holders.map(socket => new Promise((resolve, reject) => {
      socket.once("connect", () => { socket.write("GET http://tinyproxy.health/ HTTP/1.1\r\n"); resolve(); });
      socket.once("error", reject);
    })));
    await requireRequest("http://127.0.0.1:8080");
    await requireRequest("socks5h://127.0.0.1:1080");
    return { concurrentConnections: holders.length, browser: await browserProof(configuration, "http") };
  } finally { holders.forEach(socket => socket.destroy()); }
}

async function soak(configuration) {
  const urls = ["https://example.com/", "https://www.iana.org/domains/reserved",
    "https://www.rfc-editor.org/", "https://www.python.org/", "https://www.kernel.org/",
    "https://www.debian.org/", "https://www.gnu.org/", "https://www.w3.org/"];
  const deadline = Date.now() + configuration.minutes * 60000;
  const originalHttp = await pid(configuration.container, "tinyproxy");
  const originalSocks = await pid(configuration.container, "microsocks");
  let requests = 0;
  let round = 0;
  while (Date.now() < deadline) {
    const url = urls[round % urls.length];
    try {
      await Promise.all([requireRequest("http://127.0.0.1:8080", url), requireRequest("socks5h://127.0.0.1:1080", url)]);
    } catch (error) {
      const controls = await Promise.all([request("", url), request("http://127.0.0.1:8080", url),
        request("socks5h://127.0.0.1:1080", url), request("socks5h://127.0.0.1:1080", "https://example.com/")]);
      const liveness = (await containerCommand(configuration.container, "cat", "/run/vpn-sidecar/liveness")).stdout;
      fs.writeFileSync(path.join(configuration.output, "soak-failure.json"), JSON.stringify({
        at: new Date().toISOString(), requests, url, error: error.message, controls, liveness }, null, 2));
      throw error;
    }
    requests += 2;
    round += 1;
    if (round % 10 === 0) console.log(JSON.stringify({ soakRequests: requests, remainingSeconds: Math.ceil((deadline - Date.now())/1000) }));
    await sleep(2000);
  }
  assert.equal(await pid(configuration.container, "tinyproxy"), originalHttp);
  assert.equal(await pid(configuration.container, "microsocks"), originalSocks);
  return { minutes: configuration.minutes, requests, failures: 0,
    httpBrowser: await browserProof(configuration, "http"), socksBrowser: await browserProof(configuration, "socks") };
}


async function transportFault(configuration) {
  const container = configuration.container;
  const original = await pid(container, "openconnect");
  const rule = ["INPUT", "-p", "udp", "--sport", "443", "-j", "DROP"];
  await containerCommand(container, "iptables", "-I", ...rule);
  const started = Date.now();
  try {
    await sleep(12000);
    await requireRequest("http://127.0.0.1:8080");
    await requireRequest("socks5h://127.0.0.1:1080");
    assert.equal(await pid(container, "openconnect"), original);
    return { recoveryMilliseconds: Date.now() - started, sameSession: true,
      browser: await browserProof(configuration, "http") };
  } finally { await containerCommand(container, "iptables", "-D", ...rule); }
}

async function firewallVerification(configuration) {
  const container = configuration.container;
  const httpUser = (await containerCommand(container, "id", "-u", "tinyproxy")).stdout.trim();
  const assertBlocked = async user => {
    const result = await command("docker", ["exec", "--user", user, container,
      "curl", "--silent", "--show-error", "--interface", "eth0", "--max-time", "3",
      "--noproxy", "*", "http://1.1.1.1/"], true);
    assert.equal(result.code, 7, `Expected firewall connection rejection: ${result.stderr}`);
  };
  const rulesBefore = (await containerCommand(container, "iptables", "-S", "VPN_PROXY_KILLSWITCH")).stdout;
  assert.ok(rulesBefore.includes("40.96.0.0/13"));
  for (let round = 0; round < 8; round += 1) {
    await Promise.all([containerCommand(container, "/app/vpn.js", "configure-kill-switch"),
      assertBlocked(httpUser), assertBlocked("65534"), requireRequest("http://127.0.0.1:8080")]);
  }
  const rulesAfter = (await containerCommand(container, "iptables", "-S", "VPN_PROXY_KILLSWITCH")).stdout;
  assert.equal(rulesAfter, rulesBefore);
  await containerCommand(container, "env", "reason=disconnect", "/app/vpn.js", "configure-kill-switch");
  const revoked = (await containerCommand(container, "iptables", "-S", "VPN_PROXY_KILLSWITCH")).stdout;
  assert.ok(!revoked.includes("40.96.0.0/13"));
  await assertBlocked(httpUser);
  await assertBlocked("65534");
  const counters = (await containerCommand(container, "iptables", "-L", "VPN_PROXY_KILLSWITCH", "-n", "-v", "-x")).stdout;
  const rejectedPackets = counters.split("\n").filter(line => line.includes("REJECT"))
    .reduce((total, line) => total + Number(line.trim().split(/\s+/)[0]), 0);
  assert.ok(rejectedPackets >= 2, "Firewall counters did not confirm UID rejection");
  await containerCommand(container, "/app/vpn.js", "configure-kill-switch");
  assert.equal((await containerCommand(container, "iptables", "-S", "VPN_PROXY_KILLSWITCH")).stdout, rulesBefore);
  return { atomicRefreshes: 8, blockedDirectRequests: 18, rejectedPackets, exclusionRevocationAndRestore: true,
    httpBrowser: await browserProof(configuration, "http"), socksBrowser: await browserProof(configuration, "socks") };
}

async function egressFault(configuration) {
  const container = configuration.container;
  const original = await pid(container, "tinyproxy");
  const sibling = await pid(container, "microsocks");
  const user = (await containerCommand(container, "id", "-u", "tinyproxy")).stdout.trim();
  const rule = ["OUTPUT", "-o", "tun0", "-p", "tcp", "-m", "owner", "--uid-owner", user, "-j", "REJECT"];
  const started = Date.now();
  await containerCommand(container, "iptables", "-I", ...rule);
  try {
    await requireRequest("http://127.0.0.1:8080", "http://tinyproxy.health/");
    let recovered = false;
    while (Date.now() - started < 390000) {
      await requireRequest("socks5h://127.0.0.1:1080");
      const current = await pid(container, "tinyproxy");
      if (current && current !== original) { recovered = true; break; }
      await sleep(5000);
    }
    assert.ok(recovered, "Egress-only failure did not recycle HTTP proxy");
    assert.equal(await pid(container, "microsocks"), sibling);
  } finally { await containerCommand(container, "iptables", "-D", ...rule); }
  await waitHealthy(configuration);
  return { recoveryMilliseconds: Date.now() - started, siblingUnchanged: true,
    browser: await browserProof(configuration, "http") };
}

async function synRecovery(configuration) {
  const container = configuration.container;
  const originalTunnel = await pid(container, "openconnect");
  const results = [];
  for (const [protocol, processName, user] of [["http", "tinyproxy", "101"], ["socks", "microsocks", "65534"]]) {
    const proxy = protocol === "http" ? "http://127.0.0.1:8080" : "socks5h://127.0.0.1:1080";
    const originalProxy = await pid(container, processName);
    for (const every of [1000000, 1]) {
      const mark = "0x564e5001";
      const outgoing = ["OUTPUT", "-o", "tun0", "-p", "tcp", "--syn", "-d", "1.1.1.1", "--dport", "443",
        "-m", "owner", "--uid-owner", user, "-m", "connmark", "--mark", "0", "-m", "statistic",
        "--mode", "nth", "--every", String(every), "--packet", "0", "-j", "CONNMARK", "--set-mark", mark];
      const incoming = ["INPUT", "-p", "tcp", "-s", "1.1.1.1", "-m", "connmark", "--mark", mark, "-j", "DROP"];
      await containerCommand(container, "iptables", "-I", ...outgoing);
      await containerCommand(container, "iptables", "-I", ...incoming);
      const started = Date.now();
      try {
        const result = await request(proxy, "https://1.1.1.1/cdn-cgi/trace");
        const milliseconds = Date.now() - started;
        const counters = (await containerCommand(container, "iptables", "-L", "INPUT", "-n", "-v", "-x")).stdout;
        const rejected = counters.split("\n").find(line => line.includes(mark));
        const droppedPackets = Number(rejected?.trim().split(/\s+/)[0]);
        assert.ok(droppedPackets > 0, "Fault did not intercept SYN replies");
        assert.ok(milliseconds >= 2300 && milliseconds < 10000, JSON.stringify({ milliseconds, result }));
        if (every === 1000000) { assert.equal(result.code, 0, JSON.stringify(result)); assert.equal(result.status, 200); }
        else assert.notEqual(result.code, 0, "All connection attempts should fail promptly");
        results.push({ protocol, droppedConnections: every === 1 ? "all" : "first", milliseconds, droppedPackets });
      } finally {
        await containerCommand(container, "iptables", "-D", ...incoming);
        await containerCommand(container, "iptables", "-D", ...outgoing);
      }
    }
    assert.equal(await pid(container, processName), originalProxy);
    results.push(await browserProof(configuration, protocol));
  }
  assert.equal(await pid(container, "openconnect"), originalTunnel);
  return results;
}

async function run(configuration) {
  const checks = {
    proxies: async () => {
      const results = [];
      for (const target of ["tinyproxy", "microsocks"]) {
        for (const signal of ["KILL", "STOP"]) results.push(await proxyFault(configuration, target, signal));
      }
      return results;
    },
    keepalive: async () => [await keepaliveCadence(configuration), await keepaliveRedundancy(configuration)],
    tunnel: async () => {
      const results = [];
      for (const mode of ["icmp", "down", "term", "stop"]) results.push(await tunnelFault(configuration, mode));
      return results;
    },
    syn: () => synRecovery(configuration),
    transport: () => transportFault(configuration),
    firewall: () => firewallVerification(configuration),
    egress: () => egressFault(configuration),
    saturation: () => saturation(configuration),
    soak: () => soak(configuration),
    browser: async () => {
      const results = [];
      for (const protocol of ["http", "socks"]) {
        for (const url of ["https://example.com/", "https://www.python.org/", "https://www.kernel.org/",
          "https://www.iana.org/domains/reserved", "https://www.debian.org/"]) results.push(await browserProof(configuration, protocol, url));
      }
      return results;
    },
    cleanup: () => browserCleanup(configuration),
  };
  assert.ok(checks[configuration.phase], "Unknown phase");
  const result = await checks[configuration.phase]();
  fs.writeFileSync(path.join(configuration.output, `${configuration.phase}.json`), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({ phase: configuration.phase, passed: true, result }, null, 2));
}

if (require.main === module) {
  const { values } = parseArgs({ options: {
    container: { type: "string", default: "vpn-sidecar-vpn-1" },
    phase: { type: "string", default: "browser" }, minutes: { type: "string", default: "20" },
    output: { type: "string", default: `tmp/${new Date().toISOString().replace(/[-:.]/g, "")}_live_recovery` },
    session: { type: "string" },
    "browser-config": { type: "string" },
  } });
  const configuration = { ...values, minutes: Number(values.minutes), browserConfig: values["browser-config"] };
  assert.ok(configuration.session && configuration.browserConfig, "Pass --session and --browser-config explicitly");
  assert.ok(Number.isFinite(configuration.minutes) && configuration.minutes > 0, "Invalid soak minutes");
  fs.mkdirSync(configuration.output, { recursive: true });
  run(configuration).catch(error => { console.error(error); process.exitCode = 1; });
}
