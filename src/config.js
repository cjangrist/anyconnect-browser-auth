// Central runtime configuration loaded from the injected environment.
"use strict";
const path = require("node:path");
const net = require("node:net");
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BROWSER_PROFILE_DIRECTORY = process.env.VPN_BROWSER_PROFILE_DIRECTORY
  || "/tmp/vpn-browser-profile";
const BROWSER_TIMEOUT_MILLISECONDS = Number(
  process.env.VPN_BROWSER_TIMEOUT_MILLISECONDS || 180000,
);
const CURL_UPSTREAM_STATUS_EXIT_CODE = 22;
const HTTP_PROXY_PORT = 8080;
const KEEPALIVE_INTERVAL_SECONDS = Number(
  process.env.VPN_KEEPALIVE_INTERVAL_SECONDS || 1,
);
const KEEPALIVE_STALE_MILLISECONDS = Number(
  process.env.VPN_KEEPALIVE_STALE_MILLISECONDS || 15000,
);
const KEEPALIVE_TARGETS = [...new Set((
  process.env.VPN_KEEPALIVE_TARGETS || "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222,94.140.14.14"
).split(",").map((target) => target.trim()).filter(Boolean))];
const LEAK_CHECK_INTERVAL_MILLISECONDS = Number(
  process.env.VPN_LEAK_CHECK_INTERVAL_MILLISECONDS || 300000,
);
const LIVENESS_INTERVAL_MILLISECONDS = Number(
  process.env.VPN_LIVENESS_INTERVAL_MILLISECONDS || 1000,
);
const LIVENESS_STATE_FILE = process.env.VPN_LIVENESS_STATE_FILE
  || "/run/vpn-sidecar/liveness";
const LIVENESS_STATE_STALE_MILLISECONDS = Number(
  process.env.VPN_LIVENESS_STATE_STALE_MILLISECONDS || 30000,
);
const ORIGINAL_PUBLIC_IP_FILE = process.env.VPN_ORIGINAL_PUBLIC_IP_FILE
  || "/run/vpn-sidecar/original-public-ip";
const PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS = Number(
  process.env.VPN_PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS || 300000,
);
const PROXY_FAILURE_THRESHOLD = Number(
  process.env.VPN_PROXY_FAILURE_THRESHOLD || 3,
);
const PROXY_KILL_SWITCH_CHAIN = "VPN_PROXY_KILLSWITCH";
const PROXY_LISTEN_ADDRESS = "0.0.0.0";
const PROXY_PROBE_TIMEOUT_MILLISECONDS = Number(
  process.env.VPN_PROXY_PROBE_TIMEOUT_MILLISECONDS || 5000,
);
const PROXY_START_TIMEOUT_MILLISECONDS = Number(
  process.env.VPN_PROXY_START_TIMEOUT_MILLISECONDS || 15000,
);
const PROXY_SUPERVISE_INTERVAL_MILLISECONDS = Number(
  process.env.VPN_PROXY_SUPERVISE_INTERVAL_MILLISECONDS || 15000,
);
const PUBLIC_IP_FAMILY = process.env.VPN_PUBLIC_IP_FAMILY || "4";
const PUBLIC_IP_ENDPOINT_POOL = [
  "https://ifconfig.io/ip",
  "https://api.ipify.org",
  "https://icanhazip.com",
  "https://ipv4.icanhazip.com",
  "https://ipinfo.io/ip",
  "https://ifconfig.me/ip",
  "https://ident.me",
  "https://ipv4.ident.me",
  "https://tnedi.me",
  "https://checkip.amazonaws.com",
  "https://ipecho.net/plain",
  "https://myexternalip.com/raw",
  "https://wtfismyip.com/text",
  "https://ipv4.wtfismyip.com/text",
  "https://api.seeip.org",
  "https://l2.io/ip",
  "https://eth0.me",
  "https://curlmyip.net",
  "https://ipaddress.sh",
  "https://ip.tyk.nu",
  "https://whatismyip.akamai.com",
  "https://trackip.net/ip",
  "https://ifconfig.co/ip",
  "https://api.ip.sb/ip",
  "https://ip.me",
  "https://api.ipify.org/?format=text",
];
const PUBLIC_IP_ENDPOINTS = process.env.VPN_PUBLIC_IP_ENDPOINT
  ? [process.env.VPN_PUBLIC_IP_ENDPOINT]
  : PUBLIC_IP_ENDPOINT_POOL;
const RUNTIME_DIRECTORY = path.dirname(ORIGINAL_PUBLIC_IP_FILE);
const RESOLVER_CONFIGURATION_PATH = "/etc/resolv.conf";
const SOCKS_PROXY_PORT = 1080;
const SPLIT_TUNNEL_DESTINATION_PATTERN = /^[0-9a-f.:]+(\/[0-9]{1,3})?$/i;
const STATIC_DNS_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"];
const TUNNEL_INTERFACE = process.env.VPN_TUNNEL_INTERFACE || "tun0";
const VPN_SERVER = process.env.VPN_SERVER || "";
const WATCHDOG_FAILURE_THRESHOLD = Number(
  process.env.VPN_WATCHDOG_FAILURE_THRESHOLD || 3,
);
const WATCHDOG_STARTUP_GRACE_MILLISECONDS = Number(
  process.env.VPN_WATCHDOG_STARTUP_GRACE_MILLISECONDS
    || BROWSER_TIMEOUT_MILLISECONDS + 30000,
);

const COLORS = {
  debug: "\u001b[36m",
  error: "\u001b[31m",
  info: "\u001b[32m",
  reset: "\u001b[0m",
  warn: "\u001b[33m",
};


function validateRuntimeConfiguration() {
  const numericSettings = { BROWSER_TIMEOUT_MILLISECONDS, KEEPALIVE_INTERVAL_SECONDS,
    KEEPALIVE_STALE_MILLISECONDS, LEAK_CHECK_INTERVAL_MILLISECONDS,
    LIVENESS_INTERVAL_MILLISECONDS, LIVENESS_STATE_STALE_MILLISECONDS,
    PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS, PROXY_FAILURE_THRESHOLD,
    PROXY_PROBE_TIMEOUT_MILLISECONDS, PROXY_START_TIMEOUT_MILLISECONDS,
    PROXY_SUPERVISE_INTERVAL_MILLISECONDS, WATCHDOG_FAILURE_THRESHOLD,
    WATCHDOG_STARTUP_GRACE_MILLISECONDS };
  Object.entries(numericSettings).forEach(([name, value]) => {
    if (!Number.isFinite(value) || value <= 0) throw new Error(
      `VPN_${name} must be a positive finite number`);
  });
  if (KEEPALIVE_INTERVAL_SECONDS > 1) throw new Error("Keepalive interval must be at most one second");
  if (!KEEPALIVE_TARGETS.length || KEEPALIVE_TARGETS.some(target => !net.isIP(target))) {
    throw new Error("VPN_KEEPALIVE_TARGETS must contain IP addresses");
  }
  if (KEEPALIVE_STALE_MILLISECONDS <= KEEPALIVE_TARGETS.length * KEEPALIVE_INTERVAL_SECONDS * 1000 + 2000) {
    throw new Error("Keepalive stale deadline must exceed one target rotation plus two seconds");
  }
  if (!/^[a-zA-Z0-9_-]{1,15}$/.test(TUNNEL_INTERFACE)) throw new Error("Invalid tunnel interface");
  PUBLIC_IP_ENDPOINTS.forEach(endpoint => {
    if (new URL(endpoint).protocol !== "https:") throw new Error("IP endpoints must use HTTPS");
  });
}

module.exports = { validateRuntimeConfiguration, BASE32_ALPHABET, BROWSER_PROFILE_DIRECTORY, BROWSER_TIMEOUT_MILLISECONDS, CURL_UPSTREAM_STATUS_EXIT_CODE, HTTP_PROXY_PORT, KEEPALIVE_INTERVAL_SECONDS, KEEPALIVE_STALE_MILLISECONDS, KEEPALIVE_TARGETS, LEAK_CHECK_INTERVAL_MILLISECONDS, LIVENESS_INTERVAL_MILLISECONDS, LIVENESS_STATE_FILE, LIVENESS_STATE_STALE_MILLISECONDS, ORIGINAL_PUBLIC_IP_FILE, PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS, PROXY_FAILURE_THRESHOLD, PROXY_KILL_SWITCH_CHAIN, PROXY_LISTEN_ADDRESS, PROXY_PROBE_TIMEOUT_MILLISECONDS, PROXY_START_TIMEOUT_MILLISECONDS, PROXY_SUPERVISE_INTERVAL_MILLISECONDS, PUBLIC_IP_FAMILY, PUBLIC_IP_ENDPOINT_POOL, PUBLIC_IP_ENDPOINTS, RUNTIME_DIRECTORY, RESOLVER_CONFIGURATION_PATH, SOCKS_PROXY_PORT, SPLIT_TUNNEL_DESTINATION_PATTERN, STATIC_DNS_SERVERS, TUNNEL_INTERFACE, VPN_SERVER, WATCHDOG_FAILURE_THRESHOLD, WATCHDOG_STARTUP_GRACE_MILLISECONDS, COLORS };
