// network responsibilities for the VPN proxy.
"use strict";
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const state = require("./state");
const {
  HTTP_PROXY_PORT,
  ORIGINAL_PUBLIC_IP_FILE,
  PROXY_KILL_SWITCH_CHAIN,
  PUBLIC_IP_FAMILY,
  PUBLIC_IP_ENDPOINTS,
  RUNTIME_DIRECTORY,
  RESOLVER_CONFIGURATION_PATH,
  SOCKS_PROXY_PORT,
  SPLIT_TUNNEL_DESTINATION_PATTERN,
  STATIC_DNS_SERVERS,
  TUNNEL_INTERFACE,
} = require("./config");
const {
  log,
  runCommand,
  requireCommandSuccess,
  resolveSystemUserId,
  resolveSystemGroupId,
  writeAtomicState,
} = require("./runtime");

function staticResolverConfiguration() {
  return `${STATIC_DNS_SERVERS.map((server) => `nameserver ${server}`).join("\n")}\n`;
}

function assertStaticResolverConfiguration() {
  const resolverLines = fs.readFileSync(RESOLVER_CONFIGURATION_PATH, "utf8")
    .trim()
    .split("\n");
  const expectedLines = STATIC_DNS_SERVERS.map((server) => `nameserver ${server}`);
  if (JSON.stringify(resolverLines) !== JSON.stringify(expectedLines)) {
    throw new Error("Resolver configuration does not contain only the required static DNS servers");
  }
}

function writeStaticResolverConfiguration() {
  log("info", "dns.static.configure.enter", { servers: STATIC_DNS_SERVERS });
  fs.writeFileSync(RESOLVER_CONFIGURATION_PATH, staticResolverConfiguration());
  assertStaticResolverConfiguration();
  log("info", "dns.static.configure.exit", { servers: STATIC_DNS_SERVERS });
}

async function ensureFirewallOutputJump(command, userId) {
  const jumpArguments = [
    "OUTPUT",
    "-m",
    "owner",
    "--uid-owner",
    String(userId),
    "-j",
    PROXY_KILL_SWITCH_CHAIN,
  ];
  const checkResult = await requireCommandSuccess(
    command,
    ["-w", "5", "-C", ...jumpArguments],
    [0, 1],
  );
  if (checkResult.code === 1) {
    await requireCommandSuccess(command, ["-w", "5", "-I", ...jumpArguments]);
  }
}

function parseSplitTunnelDestinations(routeOutput, tunnelInterface) {
  return routeOutput
    .split("\n")
    .map((routeLine) => routeLine.trim())
    .filter((routeLine) => routeLine
      && !routeLine.startsWith("default")
      && routeLine.includes(" via ")
      && !routeLine.includes(` dev ${tunnelInterface}`))
    .map((routeLine) => routeLine.split(/\s+/)[0])
    .filter((destination) => SPLIT_TUNNEL_DESTINATION_PATTERN.test(destination));
}

async function readSplitTunnelDestinations(addressFamilyFlag) {
  const routeResult = await runCommand("ip", [addressFamilyFlag, "route", "show"]);
  if (routeResult.code !== 0) {
    log("warn", "kill_switch.routes.unreadable", { addressFamilyFlag });
    return [];
  }
  const pushedRoutes = readPushedExclusions(addressFamilyFlag === "-4" ? 4 : 6);
  return parseSplitTunnelDestinations(routeResult.stdout, TUNNEL_INTERFACE)
    .filter(destination => pushedRoutes.includes(destination.includes("/")
      ? destination : `${destination}/${addressFamilyFlag === "-4" ? 32 : 128}`));
}

function parsePushedExclusions(environment, family) {
  const prefix = family === 4 ? "CISCO_SPLIT_EXC" : "CISCO_IPV6_SPLIT_EXC";
  const count = Number(environment[prefix] || 0);
  if (!Number.isSafeInteger(count) || count < 0 || count > 4096) {
    throw new Error("Invalid pushed exclusion count");
  }
  return Array.from({ length: count }, (_, index) => {
    const address = environment[`${prefix}_${index}_ADDR`];
    const mask = Number(environment[`${prefix}_${index}_MASKLEN`]);
    if (net.isIP(address) !== family || !Number.isInteger(mask)
      || mask < 1 || mask > (family === 4 ? 32 : 128)) {
      throw new Error("Invalid pushed exclusion prefix");
    }
    return `${address}/${mask}`;
  });
}

function readPushedExclusions(family) {
  const filename = path.join(RUNTIME_DIRECTORY, `split-exclusions-${family}.json`);
  if (process.env.reason) {
    const destinations = ["connect", "reconnect", "attempt-reconnect"].includes(process.env.reason)
      ? parsePushedExclusions(process.env, family) : [];
    writeAtomicState(filename, JSON.stringify(destinations));
    return destinations;
  }
  return fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, "utf8")) : [];
}

function firewallRestoreRules(proxyPolicies, splitTunnelDestinations, tunnelInterface) {
  const chain = PROXY_KILL_SWITCH_CHAIN;
  const rules = proxyPolicies.flatMap(policy => {
    const owner = `-A ${chain} -m owner --uid-owner ${policy.userId}`;
    return [
      `${owner} -p tcp --sport ${policy.listenPort} -m conntrack --ctstate ESTABLISHED -j ACCEPT`,
      `${owner} -o ${tunnelInterface} -j ACCEPT`,
      ...splitTunnelDestinations.map(destination =>
        `${owner} ! -o ${tunnelInterface} -d ${destination} -j ACCEPT`),
      `${owner} -j REJECT`,
    ];
  });
  return ["*filter", `:${chain} - [0:0]`, ...rules, "COMMIT", ""].join("\n");
}

async function configureFirewallFamily(command, proxyPolicies, splitTunnelDestinations) {
  const rules = firewallRestoreRules(proxyPolicies, splitTunnelDestinations, TUNNEL_INTERFACE);
  const result = await runCommand(`${command}-restore`, ["--wait", "5", "--noflush"], rules);
  if (result.code !== 0) throw new Error(`Atomic firewall restore failed: ${result.stderr}`);
  for (const policy of proxyPolicies) await ensureFirewallOutputJump(command, policy.userId);
}

async function configureProxyKillSwitch(allowSplitRoutes = true) {
  log("info", "kill_switch.configure.enter", { interface: TUNNEL_INTERFACE });
  const httpProxyUserId = await resolveSystemUserId("tinyproxy");
  state.socksProxyUserId = await resolveSystemUserId("nobody");
  state.socksProxyGroupId = await resolveSystemGroupId("nogroup");
  const proxyPolicies = [
    { listenPort: HTTP_PROXY_PORT, userId: httpProxyUserId },
    { listenPort: SOCKS_PROXY_PORT, userId: state.socksProxyUserId },
  ];
  const ipv4SplitTunnelDestinations = allowSplitRoutes && fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)
    ? await readSplitTunnelDestinations("-4") : [];
  await configureFirewallFamily("iptables", proxyPolicies, ipv4SplitTunnelDestinations);
  const ipv6IsEnabled = fs.existsSync("/proc/net/if_inet6")
    && fs.readFileSync("/proc/net/if_inet6", "utf8").trim();
  let ipv6SplitTunnelDestinations = [];
  if (ipv6IsEnabled) {
    ipv6SplitTunnelDestinations = allowSplitRoutes && fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)
      ? await readSplitTunnelDestinations("-6") : [];
    await configureFirewallFamily("ip6tables", proxyPolicies, ipv6SplitTunnelDestinations);
  }
  log("info", "kill_switch.configure.exit", {
    httpProxyUserId,
    ipv4SplitTunnelRoutes: ipv4SplitTunnelDestinations.length,
    ipv6: Boolean(ipv6IsEnabled),
    ipv6SplitTunnelRoutes: ipv6SplitTunnelDestinations.length,
    socksProxyGroupId: state.socksProxyGroupId,
    socksProxyUserId: state.socksProxyUserId,
  });
}

function nextPublicIpEndpoint(endpoints = PUBLIC_IP_ENDPOINTS) {
  const endpoint = endpoints[state.publicIpEndpointCursor % endpoints.length];
  state.publicIpEndpointCursor += 1;
  return endpoint;
}

async function fetchPublicIp(proxyUrl = "", requestLabel = "direct", endpoints = PUBLIC_IP_ENDPOINTS) {
  const failures = [];
  for (let attempt = 0; attempt < Math.min(3, endpoints.length); attempt += 1) {
    const endpoint = nextPublicIpEndpoint(endpoints);
    try {
      return await fetchPublicIpFromEndpoint(endpoint, proxyUrl, requestLabel);
    } catch (error) {
      failures.push(error);
      log("warn", "public_ip.endpoint.failed", { endpoint: new URL(endpoint).hostname,
        requestLabel, error: error.message });
    }
  }
  const error = new Error(`${requestLabel}: all ${failures.length} IP endpoint attempts failed`);
  error.inconclusive = failures.some(failure => failure.inconclusive);
  throw error;
}

async function fetchPublicIpFromEndpoint(endpoint, proxyUrl = "", requestLabel = "direct") {
  const hostname = new URL(endpoint).hostname;
  const argumentsList = ["--fail", "--silent", "--show-error", "--max-time", "7",
    "--connect-timeout", "4", "--max-filesize", "1024", "--proxy", proxyUrl,
    "--write-out", "\nVPN_CURL_CONNECT_STATUS:%{http_connect}",
    "--noproxy", "", PUBLIC_IP_FAMILY === "4" ? "--ipv4" : "--ipv6", endpoint];
  log("debug", "public_ip.fetch.enter", { endpoint: hostname, requestLabel });
  const result = await runCommand("curl", argumentsList, "", 9000);
  const connectStatus = Number(result.stdout.match(/VPN_CURL_CONNECT_STATUS:(\d+)$/)?.[1] || 0);
  const address = result.stdout.replace(/\s*VPN_CURL_CONNECT_STATUS:\d+$/, "").trim();
  if (result.code !== 0) {
    const error = new Error(`${requestLabel} curl to ${hostname} failed with code ${result.code}`);
    error.inconclusive = connectStatus < 400 && [22, 60, 63].includes(result.code);
    throw error;
  }
  if (net.isIP(address) !== Number(PUBLIC_IP_FAMILY)) {
    const error = new Error(`${hostname} returned an invalid IPv${PUBLIC_IP_FAMILY} address`);
    error.inconclusive = true;
    throw error;
  }
  log("debug", "public_ip.fetch.exit", { endpoint: hostname, requestLabel });
  return address;
}

async function captureOriginalPublicIp() {
  log("info", "baseline.capture.enter");
  fs.mkdirSync(RUNTIME_DIRECTORY, { mode: 0o700, recursive: true });
  const originalPublicIp = await fetchPublicIp();
  fs.writeFileSync(ORIGINAL_PUBLIC_IP_FILE, `${originalPublicIp}\n`, { mode: 0o600 });
  log("info", "baseline.capture.exit", { addressFamily: net.isIP(originalPublicIp) });
}

function readOriginalPublicIp() {
  const originalPublicIp = fs.readFileSync(ORIGINAL_PUBLIC_IP_FILE, "utf8").trim();
  if (!net.isIP(originalPublicIp)) {
    throw new Error("Original public IP state is invalid");
  }
  return originalPublicIp;
}

function assertVpnPublicIp(currentPublicIp, originalPublicIp, requestLabel) {
  if (currentPublicIp === originalPublicIp) {
    const leak = new Error(`${requestLabel} egress returned the pre-VPN public IP`);
    leak.leaked = true;
    throw leak;
  }
}

module.exports = {
  parsePushedExclusions,
  staticResolverConfiguration,
  assertStaticResolverConfiguration,
  writeStaticResolverConfiguration,
  ensureFirewallOutputJump,
  parseSplitTunnelDestinations,
  readSplitTunnelDestinations,
  firewallRestoreRules,
  fetchPublicIpFromEndpoint,
  configureFirewallFamily,
  configureProxyKillSwitch,
  nextPublicIpEndpoint,
  fetchPublicIp,
  captureOriginalPublicIp,
  readOriginalPublicIp,
  assertVpnPublicIp,
};
