const assert = require("node:assert/strict");
const test = require("node:test");

process.env.VPN_TUNNEL_INTERFACE = "lo";
process.env.VPN_KEEPALIVE_STALE_MILLISECONDS = "15000";

const {
  PUBLIC_IP_ENDPOINT_POOL,
  generateTotp,
  parseSplitTunnelDestinations,
  recordKeepaliveReply,
  tunnelLivenessFailureReason,
} = require("../src/vpn");

const LIVE_ROUTE_TABLE = [
  "default dev tun0 scope link",
  "10.10.64.0/18 dev tun0 scope link",
  "13.107.6.152/31 via 192.168.160.1 dev eth0",
  "40.96.0.0/13 via 192.168.160.1 dev eth0",
  "52.112.0.0/14 via 192.168.160.1 dev eth0",
  "204.79.197.215 via 192.168.160.1 dev eth0",
  "192.168.160.0/20 dev eth0 proto kernel scope link src 192.168.160.2",
].join("\n");

test("generates the RFC 6238 SHA-1 test vector", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(generateTotp(secret, 59000, 8), "94287082");
});

test("collects only gateway routes that bypass the tunnel", () => {
  assert.deepEqual(parseSplitTunnelDestinations(LIVE_ROUTE_TABLE, "tun0"), [
    "13.107.6.152/31",
    "40.96.0.0/13",
    "52.112.0.0/14",
    "204.79.197.215",
  ]);
});

test("never treats the default route as a split-tunnel destination", () => {
  const routeOutput = "default via 192.168.160.1 dev eth0";
  assert.deepEqual(parseSplitTunnelDestinations(routeOutput, "tun0"), []);
});

test("ignores routes that already leave through the tunnel", () => {
  const routeOutput = "10.0.0.0/8 via 10.10.95.60 dev tun0";
  assert.deepEqual(parseSplitTunnelDestinations(routeOutput, "tun0"), []);
});

test("ignores link-scoped routes that have no gateway", () => {
  const routeOutput = "192.168.160.0/20 dev eth0 proto kernel scope link src 192.168.160.2";
  assert.deepEqual(parseSplitTunnelDestinations(routeOutput, "tun0"), []);
});

test("returns nothing once the tunnel routes are torn down", () => {
  assert.deepEqual(parseSplitTunnelDestinations("", "tun0"), []);
});

test("collects IPv6 gateway routes that bypass the tunnel", () => {
  const routeOutput = [
    "default via fe80::1 dev tun0 metric 1024 pref medium",
    "2603:1030::/44 via fe80::1 dev eth0 metric 1024 pref medium",
    "fe80::/64 dev tun0 proto kernel metric 256 pref medium",
  ].join("\n");
  assert.deepEqual(parseSplitTunnelDestinations(routeOutput, "tun0"), ["2603:1030::/44"]);
});

test("rejects route destinations that are not addresses", () => {
  const routeOutput = "unreachable via 192.168.160.1 dev eth0";
  assert.deepEqual(parseSplitTunnelDestinations(routeOutput, "tun0"), []);
});

test("spreads leak checks over at least 25 endpoints", () => {
  assert.ok(
    PUBLIC_IP_ENDPOINT_POOL.length >= 25,
    `expected >= 25 endpoints, got ${PUBLIC_IP_ENDPOINT_POOL.length}`,
  );
});

test("never repeats an endpoint URL in the rotation pool", () => {
  assert.equal(new Set(PUBLIC_IP_ENDPOINT_POOL).size, PUBLIC_IP_ENDPOINT_POOL.length);
});

test("only rotates over parseable HTTPS endpoints", () => {
  PUBLIC_IP_ENDPOINT_POOL.forEach((endpoint) => {
    assert.equal(new URL(endpoint).protocol, "https:", `${endpoint} must be HTTPS`);
  });
});

test("treats a fresh ping reply as tunnel liveness", () => {
  recordKeepaliveReply("64 bytes from 1.1.1.1: icmp_seq=7 ttl=63 time=0.31 ms");
  assert.equal(tunnelLivenessFailureReason(), "");
});

test("ignores ping lines that are not replies", () => {
  recordKeepaliveReply("64 bytes from 1.1.1.1: icmp_seq=1 ttl=63 time=0.31 ms");
  recordKeepaliveReply("PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.");
  recordKeepaliveReply("From 10.0.0.1 icmp_seq=2 Destination Host Unreachable");
  recordKeepaliveReply("ping: sendmsg: Network is unreachable");
  assert.equal(tunnelLivenessFailureReason(), "");
});

test("reports staleness once replies stop arriving", async () => {
  process.env.VPN_KEEPALIVE_STALE_MILLISECONDS = "15000";
  recordKeepaliveReply("64 bytes from 1.1.1.1: icmp_seq=9 ttl=63 time=0.31 ms");
  assert.equal(tunnelLivenessFailureReason(), "");
  Object.keys(require.cache).filter((filename) => filename.includes("/src/"))
    .forEach((filename) => { delete require.cache[filename]; });
  process.env.VPN_KEEPALIVE_STALE_MILLISECONDS = "1";
  const staleModule = require("../src/vpn");
  staleModule.recordKeepaliveReply("64 bytes from 1.1.1.1: icmp_seq=1 ttl=63 time=0.3 ms");
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.match(staleModule.tunnelLivenessFailureReason(), /keepalive reply for \d+ms/);
});

test("pings several targets so one blocked responder cannot fake an outage", () => {
  Object.keys(require.cache).filter((filename) => filename.includes("/src/"))
    .forEach((filename) => { delete require.cache[filename]; });
  const defaultTargetsModule = require("../src/vpn");
  assert.ok(
    defaultTargetsModule.KEEPALIVE_TARGETS.length >= 2,
    "at least two keepalive targets are required for redundancy",
  );
  assert.ok(defaultTargetsModule.KEEPALIVE_TARGETS.includes("1.1.1.1"));
});

test("parses a custom keepalive target list, trimming blanks", () => {
  Object.keys(require.cache).filter((filename) => filename.includes("/src/"))
    .forEach((filename) => { delete require.cache[filename]; });
  process.env.VPN_KEEPALIVE_TARGETS = " 9.9.9.9 , , 1.0.0.1 ";
  const customTargetsModule = require("../src/vpn");
  assert.deepEqual(customTargetsModule.KEEPALIVE_TARGETS, ["9.9.9.9", "1.0.0.1"]);
  delete process.env.VPN_KEEPALIVE_TARGETS;
});

test("reports an absent tunnel interface ahead of keepalive staleness", () => {
  Object.keys(require.cache).filter((filename) => filename.includes("/src/"))
    .forEach((filename) => { delete require.cache[filename]; });
  process.env.VPN_TUNNEL_INTERFACE = "tun-does-not-exist";
  const missingInterfaceModule = require("../src/vpn");
  missingInterfaceModule.recordKeepaliveReply("64 bytes from 1.1.1.1: icmp_seq=1 ttl=63 time=0.3 ms");
  assert.match(
    missingInterfaceModule.tunnelLivenessFailureReason(),
    /tunnel interface tun-does-not-exist is absent/,
  );
  process.env.VPN_TUNNEL_INTERFACE = "lo";
});
