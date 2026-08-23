#!/usr/bin/env node

/*
 * Autonomous AnyConnect VPN proxy. OpenConnect owns Cisco's encrypted SSO
 * callback, Playwright supplies credentials and MFA, and UID-scoped firewall
 * rules keep the supervised HTTP and SOCKS proxies fail-closed.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const process = require("node:process");
const { spawn } = require("node:child_process");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BROWSER_HEADLESS = !["0", "false", "no"].includes(
  String(process.env.VPN_BROWSER_HEADLESS || "true").toLowerCase(),
);
const BROWSER_PROFILE_DIRECTORY = process.env.VPN_BROWSER_PROFILE_DIRECTORY
  || "/tmp/vpn-browser-profile";
const BROWSER_TIMEOUT_MILLISECONDS = Number(
  process.env.VPN_BROWSER_TIMEOUT_MILLISECONDS || 180000,
);
const HTTP_PROXY_PORT = 8080;
const ORIGINAL_PUBLIC_IP_FILE = process.env.VPN_ORIGINAL_PUBLIC_IP_FILE
  || "/run/vpn-sidecar/original-public-ip";
const PROXY_KILL_SWITCH_CHAIN = "VPN_PROXY_KILLSWITCH";
const PROXY_LISTEN_ADDRESS = "0.0.0.0";
const PROXY_START_TIMEOUT_MILLISECONDS = 5000;
const PUBLIC_IP_FAMILY = process.env.VPN_PUBLIC_IP_FAMILY || "4";
const PUBLIC_IP_ENDPOINT = process.env.VPN_PUBLIC_IP_ENDPOINT
  || "https://ifconfig.io/ip";
const RUNTIME_DIRECTORY = path.dirname(ORIGINAL_PUBLIC_IP_FILE);
const RESOLVER_CONFIGURATION_PATH = "/etc/resolv.conf";
const SOCKS_PROXY_PORT = 1080;
const STATIC_DNS_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"];
const TUNNEL_INTERFACE = process.env.VPN_TUNNEL_INTERFACE || "tun0";
const VPN_SERVER = process.env.VPN_SERVER || "";
const WATCHDOG_FAILURE_THRESHOLD = Number(
  process.env.VPN_WATCHDOG_FAILURE_THRESHOLD || 3,
);
const WATCHDOG_INTERVAL_MILLISECONDS = Number(
  process.env.VPN_WATCHDOG_INTERVAL_MILLISECONDS || 30000,
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

let activeOpenConnectProcess = null;
const activeProxyProcesses = new Map();
let proxyOperationPromise = Promise.resolve();
let playwrightErrors = null;
let shutdownRequested = false;
let socksProxyGroupId = null;
let socksProxyUserId = null;

function log(level, event, details = {}) {
  const serializedDetails = Object.entries(details)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(" ");
  const suffix = serializedDetails ? ` ${serializedDetails}` : "";
  const color = COLORS[level] || COLORS.info;
  process.stderr.write(
    `${color}${new Date().toISOString()} ${level.toUpperCase()} ${event}${suffix}${COLORS.reset}\n`,
  );
}

function runCommand(command, argumentsList) {
  return new Promise((resolve, reject) => {
    const commandProcess = spawn(command, argumentsList, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    commandProcess.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    commandProcess.stderr.on("data", (chunk) => stderrChunks.push(chunk));
    let settled = false;
    commandProcess.once("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    commandProcess.once("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve({
        code,
        stderr: Buffer.concat(stderrChunks).toString("utf8").trim(),
        stdout: Buffer.concat(stdoutChunks).toString("utf8").trim(),
      });
    });
  });
}

function isProcessRunning(childProcess) {
  return Boolean(childProcess.pid)
    && childProcess.exitCode === null
    && childProcess.signalCode === null;
}

async function requireCommandSuccess(command, argumentsList, acceptedExitCodes = [0]) {
  const result = await runCommand(command, argumentsList);
  if (!acceptedExitCodes.includes(result.code)) {
    throw new Error(
      `${command} failed with code ${result.code}: ${result.stderr || "no error output"}`,
    );
  }
  return result;
}

async function resolveSystemUserId(username) {
  const result = await requireCommandSuccess("id", ["-u", username]);
  const userId = Number(result.stdout);
  if (!Number.isSafeInteger(userId) || userId < 1) {
    throw new Error(`System user ${username} has an invalid user ID`);
  }
  return userId;
}

async function resolveSystemGroupId(groupName) {
  const result = await requireCommandSuccess("getent", ["group", groupName]);
  const groupFields = result.stdout.split(":");
  const groupId = Number(groupFields[2]);
  if (!Number.isSafeInteger(groupId) || groupId < 1) {
    throw new Error(`System group ${groupName} has an invalid group ID`);
  }
  return groupId;
}

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
  const resolverConfiguration = staticResolverConfiguration();
  const temporaryPath = path.join(
    RUNTIME_DIRECTORY,
    `resolv.conf.${process.pid}.${Date.now()}`,
  );
  fs.mkdirSync(RUNTIME_DIRECTORY, { mode: 0o700, recursive: true });
  fs.writeFileSync(temporaryPath, resolverConfiguration, { mode: 0o644 });
  try {
    fs.copyFileSync(temporaryPath, RESOLVER_CONFIGURATION_PATH);
    assertStaticResolverConfiguration();
  } finally {
    fs.unlinkSync(temporaryPath);
  }
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

async function configureFirewallFamily(command, proxyPolicies) {
  await requireCommandSuccess(
    command,
    ["-w", "5", "-N", PROXY_KILL_SWITCH_CHAIN],
    [0, 1],
  );
  await requireCommandSuccess(command, ["-w", "5", "-F", PROXY_KILL_SWITCH_CHAIN]);
  for (const policy of proxyPolicies) {
    const ownerArguments = ["-m", "owner", "--uid-owner", String(policy.userId)];
    await requireCommandSuccess(command, [
      "-w", "5", "-A", PROXY_KILL_SWITCH_CHAIN,
      ...ownerArguments,
      "-p", "tcp", "--sport", String(policy.listenPort),
      "-m", "conntrack", "--ctstate", "ESTABLISHED",
      "-j", "ACCEPT",
    ]);
    await requireCommandSuccess(command, [
      "-w", "5", "-A", PROXY_KILL_SWITCH_CHAIN,
      ...ownerArguments,
      "-o", TUNNEL_INTERFACE,
      "-j", "ACCEPT",
    ]);
    await requireCommandSuccess(command, [
      "-w", "5", "-A", PROXY_KILL_SWITCH_CHAIN,
      ...ownerArguments,
      "-j", "REJECT",
    ]);
    await ensureFirewallOutputJump(command, policy.userId);
  }
}

async function configureProxyKillSwitch() {
  log("info", "kill_switch.configure.enter", { interface: TUNNEL_INTERFACE });
  const httpProxyUserId = await resolveSystemUserId("tinyproxy");
  socksProxyUserId = await resolveSystemUserId("nobody");
  socksProxyGroupId = await resolveSystemGroupId("nogroup");
  const proxyPolicies = [
    { listenPort: HTTP_PROXY_PORT, userId: httpProxyUserId },
    { listenPort: SOCKS_PROXY_PORT, userId: socksProxyUserId },
  ];
  await configureFirewallFamily("iptables", proxyPolicies);
  const ipv6IsEnabled = fs.existsSync("/proc/net/if_inet6")
    && fs.readFileSync("/proc/net/if_inet6", "utf8").trim();
  if (ipv6IsEnabled) {
    await configureFirewallFamily("ip6tables", proxyPolicies);
  }
  log("info", "kill_switch.configure.exit", {
    httpProxyUserId,
    ipv6: Boolean(ipv6IsEnabled),
    socksProxyGroupId,
    socksProxyUserId,
  });
}

function readCredentials(environment = process.env) {
  log("debug", "credentials.read.enter");
  const environmentKeys = {
    password: "VPN_PASSWORD",
    totpSecret: "VPN_TOTP_SECRET",
    username: "VPN_USERNAME",
  };
  const missingKeys = Object.values(environmentKeys)
    .filter((environmentKey) => !environment[environmentKey]);
  if (missingKeys.length) {
    throw new Error(`Environment is missing required fields: ${missingKeys.join(", ")}`);
  }
  const credentials = Object.fromEntries(
    Object.entries(environmentKeys)
      .map(([credentialKey, environmentKey]) => [credentialKey, environment[environmentKey]]),
  );
  log("debug", "credentials.read.exit", {
    fields: ["username", "password", "totpSecret"],
  });
  return credentials;
}

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

function normalizeTotpSecret(rawSecret) {
  if (rawSecret.toLowerCase().startsWith("otpauth://")) {
    const parsedUri = new URL(rawSecret);
    const uriSecret = parsedUri.searchParams.get("secret");
    if (!uriSecret) {
      throw new Error("TOTP URI has no secret parameter");
    }
    return uriSecret;
  }
  return rawSecret.replace(/^base32:/i, "");
}

function decodeBase32(rawSecret) {
  const normalizedSecret = normalizeTotpSecret(rawSecret)
    .toUpperCase()
    .replace(/[\s=-]/g, "");
  if (!normalizedSecret || [...normalizedSecret].some(
    (character) => !BASE32_ALPHABET.includes(character),
  )) {
    throw new Error("TOTP secret is not valid base32");
  }
  let bitBuffer = 0;
  let bitCount = 0;
  const outputBytes = [];
  for (const character of normalizedSecret) {
    bitBuffer = (bitBuffer << 5) | BASE32_ALPHABET.indexOf(character);
    bitCount += 5;
    while (bitCount >= 8) {
      bitCount -= 8;
      outputBytes.push((bitBuffer >> bitCount) & 0xff);
    }
  }
  return Buffer.from(outputBytes);
}

function generateTotp(rawSecret, timestampMilliseconds = Date.now(), digits = 6) {
  const counter = BigInt(Math.floor(timestampMilliseconds / 30000));
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter);
  const digest = crypto.createHmac("sha1", decodeBase32(rawSecret))
    .update(counterBuffer)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binaryCode = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binaryCode % (10 ** digits)).padStart(digits, "0");
}

function safeLocation(rawUrl) {
  try {
    const parsedUrl = new URL(rawUrl);
    return `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
  } catch {
    return "unparseable-url";
  }
}

function sanitizeAuthenticationMessage(rawMessage, credentials) {
  const credentialValues = Object.values(credentials).filter(Boolean);
  const redactedMessage = credentialValues.reduce((message, credentialValue) => {
    const escapedValue = credentialValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return message.replace(new RegExp(escapedValue, "gi"), "[credential]");
  }, String(rawMessage));
  return redactedMessage.replace(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    "[account]",
  );
}

async function fetchPublicIp(proxyUrl = "", requestLabel = "direct") {
  log("debug", "public_ip.fetch.enter", {
    endpoint: new URL(PUBLIC_IP_ENDPOINT).hostname,
  });
  const curlArguments = [
    "--fail",
    "--silent",
    "--show-error",
    "--max-time",
    "7",
    PUBLIC_IP_FAMILY === "4" ? "--ipv4" : "--ipv6",
  ];
  if (proxyUrl) {
    curlArguments.push("--proxy", proxyUrl);
  }
  curlArguments.push(PUBLIC_IP_ENDPOINT);
  const curlResult = await new Promise((resolve, reject) => {
    const curlProcess = spawn("curl", curlArguments, { stdio: ["ignore", "pipe", "pipe"] });
    const stdoutChunks = [];
    const stderrChunks = [];
    curlProcess.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    curlProcess.stderr.on("data", (chunk) => stderrChunks.push(chunk));
    let settled = false;
    curlProcess.once("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    curlProcess.once("close", (code) => {
      if (!settled) {
        settled = true;
        resolve({ code, stderrChunks, stdoutChunks });
      }
    });
  });
  if (curlResult.code !== 0) {
    const errorMessage = Buffer.concat(curlResult.stderrChunks).toString("utf8").trim();
    throw new Error(
      `${requestLabel} curl to ${new URL(PUBLIC_IP_ENDPOINT).hostname} failed with code ${curlResult.code}: ${errorMessage}`,
    );
  }
  const candidateIp = Buffer.concat(curlResult.stdoutChunks).toString("utf8").trim();
  if (!net.isIP(candidateIp)) {
    throw new Error(
      `${requestLabel} curl to ${new URL(PUBLIC_IP_ENDPOINT).hostname} returned an invalid public IP address`,
    );
  }
  if (net.isIP(candidateIp) !== Number(PUBLIC_IP_FAMILY)) {
    throw new Error(
      `${requestLabel} curl to ${new URL(PUBLIC_IP_ENDPOINT).hostname} returned an IP outside IPv${PUBLIC_IP_FAMILY}`,
    );
  }
  log("debug", "public_ip.fetch.exit", {
    endpoint: new URL(PUBLIC_IP_ENDPOINT).hostname,
  });
  return candidateIp;
}

async function captureOriginalPublicIp() {
  log("info", "baseline.capture.enter");
  fs.mkdirSync(RUNTIME_DIRECTORY, { mode: 0o700, recursive: true });
  const originalPublicIp = await fetchPublicIp();
  fs.writeFileSync(ORIGINAL_PUBLIC_IP_FILE, `${originalPublicIp}\n`, { mode: 0o600 });
  log("info", "baseline.capture.exit", { addressFamily: net.isIP(originalPublicIp) });
}

async function firstVisibleLocator(page, selectors) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if (await locator.count() && await locator.isVisible()) {
      return locator;
    }
  }
  return null;
}

async function firstVisibleText(page, selectors) {
  const locator = await firstVisibleLocator(page, selectors);
  if (!locator) {
    return "";
  }
  return (await locator.innerText()).trim();
}

async function fillFirstVisible(page, selectors, value, actionName) {
  const locator = await firstVisibleLocator(page, selectors);
  if (!locator) {
    return false;
  }
  await locator.fill(value);
  if (await locator.inputValue() !== value) {
    throw new Error(`Browser did not retain the supplied ${actionName} field value`);
  }
  log("info", "browser.form.filled", { field: actionName });
  return true;
}

async function fillAndPressEnter(page, selectors, value, actionName) {
  const locator = await firstVisibleLocator(page, selectors);
  if (!locator) {
    return false;
  }
  await locator.fill(value);
  if (await locator.inputValue() !== value) {
    throw new Error(`Browser did not retain the supplied ${actionName} field value`);
  }
  log("info", "browser.form.filled", { field: actionName });
  await locator.press("Enter");
  log("info", "browser.control.pressed", { control: `${actionName}-Enter` });
  await page.waitForTimeout(600);
  return true;
}

async function clickFirstVisible(page, selectors, actionName) {
  const locator = await firstVisibleLocator(page, selectors);
  if (!locator) {
    return false;
  }
  return clickLocator(locator, actionName);
}

async function clickLocator(locator, actionName) {
  try {
    await locator.click({ timeout: 5000 });
  } catch (error) {
    if (!playwrightErrors || !(error instanceof playwrightErrors.TimeoutError)) {
      throw error;
    }
    log("warn", "browser.control.retry", {
      control: actionName,
      reason: "transient-timeout",
    });
    return false;
  }
  log("info", "browser.control.clicked", { control: actionName });
  return true;
}

async function clickFirstMatchingText(page, patterns, actionName) {
  for (const pattern of patterns) {
    const locator = page.getByText(pattern, { exact: false }).first();
    if (await locator.count() && await locator.isVisible()) {
      return clickLocator(locator, actionName);
    }
  }
  return false;
}

async function submitCurrentForm(page, preferredSelectors) {
  const submitted = await clickFirstVisible(page, preferredSelectors, "submit");
  if (!submitted) {
    await page.keyboard.press("Enter");
    log("info", "browser.control.pressed", { control: "Enter" });
  }
  await page.waitForTimeout(600);
}

async function handleRememberedAccount(page, credentials, state) {
  if (state.lastAction !== "account-picker") {
    const accountTileLocators = [
      page.locator('#tilesHolder').getByText(credentials.username, { exact: false }).first(),
      page.locator('[data-testid="account-list"]')
        .getByText(credentials.username, { exact: false }).first(),
    ];
    for (const accountTileLocator of accountTileLocators) {
      if (await accountTileLocator.count() && await accountTileLocator.isVisible()) {
        await accountTileLocator.click();
        state.lastAction = "account-picker";
        log("info", "browser.control.clicked", { control: "remembered-account" });
        await page.waitForTimeout(600);
        return true;
      }
    }
  }
  if (state.lastAction === "none"
    && await clickFirstVisible(page, ['#otherTileText'], "use-another-account")) {
    state.lastAction = "other-account";
    await page.waitForTimeout(600);
    return true;
  }
  return false;
}

async function handleCredentialForm(page, credentials, state) {
  const passwordSelectors = ['input[name="passwd"]', 'input[type="password"]'];
  const focusedPasswordSelectors = [
    'input[name="passwd"]:focus',
    'input[type="password"]:focus',
  ];
  if (await firstVisibleLocator(page, focusedPasswordSelectors)) {
    if (state.lastAction === "password") {
      return false;
    }
    await fillAndPressEnter(
      page,
      focusedPasswordSelectors,
      credentials.password,
      "password",
    );
    state.lastAction = "password";
    return true;
  }
  const usernameSelectors = [
    'input[name="loginfmt"]',
    'input[type="email"]',
  ];
  const focusedUsernameSelectors = [
    'input[name="loginfmt"]:focus',
    'input[type="email"]:focus',
  ];
  const focusedUsernameLocator = await firstVisibleLocator(page, focusedUsernameSelectors);
  const usernameIsExpected = focusedUsernameLocator
    || (["none", "account-picker", "other-account"].includes(state.lastAction)
      && await firstVisibleLocator(page, usernameSelectors));
  if (usernameIsExpected) {
    if (state.lastAction === "username") {
      return false;
    }
    await fillFirstVisible(
      page,
      focusedUsernameLocator ? focusedUsernameSelectors : usernameSelectors,
      credentials.username,
      "username",
    );
    await submitCurrentForm(page, ['#idSIButton9', 'input[type="submit"]']);
    state.lastAction = "username";
    return true;
  }
  return false;
}

async function handleTotpForm(page, credentials, state) {
  const totpSelectors = [
    '#idTxtBx_SAOTCC_OTC',
    'input[name="otc"]',
    'input[name="VerificationCode"]',
    'input[type="tel"]',
  ];
  if (!await firstVisibleLocator(page, totpSelectors)) {
    return false;
  }
  if (state.lastAction === "totp") {
    return false;
  }
  const totpCode = generateTotp(credentials.totpSecret);
  await fillAndPressEnter(page, totpSelectors, totpCode, "totp");
  state.lastAction = "totp";
  state.totpAttemptCount += 1;
  return true;
}

async function handleMfaChoice(page, state) {
  if (state.lastAction !== "mfa-method" && await clickFirstVisible(page, [
    '[data-value="PhoneAppOTP"]',
    '[data-value="SoftwareTokenBasedTOTP"]',
  ], "verification-code-method")) {
    state.lastAction = "mfa-method";
    await page.waitForTimeout(600);
    return true;
  }
  if (state.lastAction !== "mfa-alternative" && await clickFirstMatchingText(page, [
    /I can.t use my Microsoft Authenticator app right now/i,
    /use a verification code/i,
    /enter a code/i,
    /use a code/i,
  ], "verification-code-path")) {
    state.lastAction = "mfa-alternative";
    await page.waitForTimeout(600);
    return true;
  }
  if (state.lastAction !== "mfa-other-methods" && await clickFirstVisible(page, [
    '#signInAnotherWay',
    '[data-bind*="showAuthMethods"]',
  ], "sign-in-another-way")) {
    state.lastAction = "mfa-other-methods";
    await page.waitForTimeout(600);
    return true;
  }
  return false;
}

async function isStaySignedInPage(page) {
  const kmsiMarker = await firstVisibleLocator(page, [
    '#KmsiDescription',
    '[data-testid="kmsiDescription"]',
  ]);
  if (kmsiMarker) {
    return true;
  }
  const staySignedInText = page.getByText(/^Stay signed in\?$/i).first();
  return Boolean(await staySignedInText.count() && await staySignedInText.isVisible());
}

async function handlePostAuthenticationPage(page, state) {
  if (await isStaySignedInPage(page)
    && state.lastAction !== "kmsi-no"
    && await clickFirstVisible(page, ['#idBtn_Back'], "stay-signed-in-no")) {
    state.lastAction = "kmsi-no";
    await page.waitForTimeout(600);
    return true;
  }
  if (state.lastAction !== "continue"
    && await clickFirstMatchingText(page, [/^Continue$/i], "continue")) {
    state.lastAction = "continue";
    await page.waitForTimeout(600);
    return true;
  }
  return false;
}

async function detectAuthenticationError(page, credentials, state) {
  const credentialErrorText = await firstVisibleText(page, [
    '#usernameError',
    '#passwordError',
    '[data-testid="usernameError"]',
  ]);
  if (credentialErrorText && ["username", "password"].includes(state.lastAction)) {
    log("error", "browser.authentication.rejected", {
      message: sanitizeAuthenticationMessage(credentialErrorText, credentials),
    });
    throw new Error("The identity provider rejected the supplied username or password");
  }
  const totpErrorText = await firstVisibleText(page, [
    '#idSpan_SAOTCC_Error_OTC',
    '[data-testid="otcError"]',
  ]);
  if (totpErrorText && state.lastAction === "totp") {
    log("warn", "browser.totp.rejected", {
      message: sanitizeAuthenticationMessage(totpErrorText, credentials),
    });
    if (state.totpAttemptCount >= 3) {
      throw new Error("The identity provider rejected three generated TOTP codes");
    }
    const millisecondsUntilNextPeriod = 30000 - (Date.now() % 30000) + 750;
    log("warn", "browser.totp.retry_wait", {
      milliseconds: millisecondsUntilNextPeriod,
    });
    await page.waitForTimeout(millisecondsUntilNextPeriod);
    state.lastAction = "totp-retry";
  }
}

async function driveAuthenticationPage(page, credentials, state) {
  await detectAuthenticationError(page, credentials, state);
  if (await handleTotpForm(page, credentials, state)) {
    return true;
  }
  if (await handleRememberedAccount(page, credentials, state)) {
    return true;
  }
  if (await handleCredentialForm(page, credentials, state)) {
    return true;
  }
  if (await handleMfaChoice(page, state)) {
    return true;
  }
  return handlePostAuthenticationPage(page, state);
}

async function runBrowser(startUrl) {
  log("info", "browser.start.enter", {
    headless: BROWSER_HEADLESS,
    location: safeLocation(startUrl),
  });
  const credentials = readCredentials();
  const { chromium, errors } = require("playwright");
  playwrightErrors = errors;
  fs.mkdirSync(BROWSER_PROFILE_DIRECTORY, { mode: 0o700, recursive: true });
  const browserContext = await chromium.launchPersistentContext(
    BROWSER_PROFILE_DIRECTORY,
    {
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
      headless: BROWSER_HEADLESS,
      ignoreHTTPSErrors: false,
    },
  );
  let callbackObserved = false;
  let lastBrowserStateSignature = "";
  const state = { lastAction: "none", totpAttemptCount: 0 };
  browserContext.on("response", (response) => {
    try {
      const responseUrl = new URL(response.url());
      if (["localhost", "127.0.0.1", "[::1]"].includes(responseUrl.hostname)
        && responseUrl.port === "29786"
        && responseUrl.pathname.startsWith("/api/sso/")) {
        callbackObserved = true;
        log("info", "browser.sso_callback.accepted", { status: response.status() });
      }
    } catch {
      log("debug", "browser.response.url_unparseable");
    }
  });
  const initialPage = browserContext.pages()[0] || await browserContext.newPage();
  const deadline = Date.now() + BROWSER_TIMEOUT_MILLISECONDS;
  try {
    await initialPage.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 60000 });
    while (Date.now() < deadline && !callbackObserved) {
      const pages = browserContext.pages();
      const activePage = pages[pages.length - 1] || initialPage;
      const browserState = {
        location: safeLocation(activePage.url()),
        title: await activePage.title(),
      };
      const browserStateSignature = JSON.stringify(browserState);
      if (browserStateSignature !== lastBrowserStateSignature) {
        log("debug", "browser.state", browserState);
        lastBrowserStateSignature = browserStateSignature;
      }
      const acted = await driveAuthenticationPage(activePage, credentials, state);
      if (!acted) {
        await activePage.waitForTimeout(300);
      }
    }
    if (!callbackObserved) {
      throw new Error("Timed out before Cisco accepted the SSO callback");
    }
    await new Promise((resolve) => setTimeout(resolve, 750));
    log("info", "browser.start.exit", { result: "authenticated" });
  } finally {
    await browserContext.close();
  }
}

function sanitizeOpenConnectLine(line) {
  if (/(cookie|token|session-id|x-dtls-session-id|sso-v2-login|samlrequest|\/api\/sso\/)/i
    .test(line)) {
    return "[authentication detail redacted]";
  }
  return line.replace(/https?:\/\/[^\s]+/g, (rawUrl) => safeLocation(rawUrl));
}

function streamProcessLines(stream, processName, streamName, sanitizeLine = (line) => line) {
  let bufferedText = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    bufferedText += chunk;
    const lines = bufferedText.split(/\r?\n/);
    bufferedText = lines.pop() || "";
    lines.filter(Boolean).forEach((line) => {
      log("info", `${processName}.output`, {
        stream: streamName,
        message: sanitizeLine(line),
      });
    });
  });
  stream.on("end", () => {
    if (bufferedText) {
      log("info", `${processName}.output`, {
        stream: streamName,
        message: sanitizeLine(bufferedText),
      });
    }
  });
}

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
      socket.destroy();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    socket.setTimeout(1000);
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
  if (!Number.isSafeInteger(socksProxyGroupId) || !Number.isSafeInteger(socksProxyUserId)) {
    throw new Error("SOCKS proxy user and group IDs are not configured");
  }
  return [
    {
      arguments: ["-d", "-c", "/etc/tinyproxy/tinyproxy.conf"],
      command: "tinyproxy",
      name: "http_proxy",
      port: HTTP_PROXY_PORT,
      probe: probeHttpProxy,
    },
    {
      arguments: ["-i", PROXY_LISTEN_ADDRESS, "-p", String(SOCKS_PROXY_PORT)],
      command: "microsocks",
      gid: socksProxyGroupId,
      name: "socks_proxy",
      port: SOCKS_PROXY_PORT,
      probe: probeSocksProxy,
      uid: socksProxyUserId,
    },
  ];
}

function queueProxyOperation(operation) {
  const queuedOperation = proxyOperationPromise.then(operation, operation);
  proxyOperationPromise = queuedOperation.catch(() => {});
  return queuedOperation;
}

function canServeProxyTraffic() {
  return !shutdownRequested
    && Boolean(activeOpenConnectProcess)
    && isProcessRunning(activeOpenConnectProcess);
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
  activeProxyProcesses.set(definition.name, proxyProcess);
  streamProcessLines(proxyProcess.stdout, definition.name, "stdout");
  streamProcessLines(proxyProcess.stderr, definition.name, "stderr");
  proxyProcess.once("error", (error) => {
    if (activeProxyProcesses.get(definition.name) === proxyProcess) {
      activeProxyProcesses.delete(definition.name);
    }
    log("error", `${definition.name}.start.error`, { error: error.message });
  });
  proxyProcess.once("exit", (code, signal) => {
    if (activeProxyProcesses.get(definition.name) === proxyProcess) {
      activeProxyProcesses.delete(definition.name);
    }
    log("warn", `${definition.name}.start.exit`, { code, signal });
  });
}

async function ensureProxyProcessesRunning() {
  await queueProxyOperation(async () => {
    if (!canServeProxyTraffic()) {
      log("warn", "proxies.start.skipped", { reason: "openconnect-not-running" });
      return;
    }
    const definitions = proxyDefinitions();
    definitions
      .filter((definition) => !activeProxyProcesses.has(definition.name))
      .forEach(startProxyProcess);
    await Promise.all(definitions.map(
      (definition) => waitForProxyProbe(definition.probe, definition.port),
    ));
    log("info", "proxies.ready", {
      httpPort: HTTP_PROXY_PORT,
      socksPort: SOCKS_PROXY_PORT,
    });
  });
}

function waitForProcessExit(childProcess, timeoutMilliseconds) {
  if (!isProcessRunning(childProcess)) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let killTimeout = null;
    let settled = false;
    const complete = (error = null) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (killTimeout) {
        clearTimeout(killTimeout);
      }
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const timeout = setTimeout(() => {
      if (isProcessRunning(childProcess)) {
        const killed = childProcess.kill("SIGKILL");
        if (!killed) {
          complete(new Error(`Process ${childProcess.pid} could not be terminated`));
          return;
        }
        killTimeout = setTimeout(() => {
          complete(new Error(`Process ${childProcess.pid} did not exit after SIGKILL`));
        }, timeoutMilliseconds);
      }
    }, timeoutMilliseconds);
    childProcess.once("exit", () => complete());
  });
}

async function stopProxyProcesses(reason) {
  await queueProxyOperation(async () => {
    const proxyProcesses = [...activeProxyProcesses.values()];
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

async function monitorTunnel(openConnectProcess) {
  log("info", "watchdog.start", {
    failureThreshold: WATCHDOG_FAILURE_THRESHOLD,
    intervalMilliseconds: WATCHDOG_INTERVAL_MILLISECONDS,
  });
  const startupDeadline = Date.now() + WATCHDOG_STARTUP_GRACE_MILLISECONDS;
  let consecutiveFailures = 0;
  let tunnelWasObserved = false;
  while (!shutdownRequested && isProcessRunning(openConnectProcess)) {
    const checkDelayMilliseconds = tunnelWasObserved
      ? WATCHDOG_INTERVAL_MILLISECONDS
      : Math.min(WATCHDOG_INTERVAL_MILLISECONDS, 1000);
    await new Promise((resolve) => setTimeout(resolve, checkDelayMilliseconds));
    if (shutdownRequested || !isProcessRunning(openConnectProcess)) {
      break;
    }
    const tunnelExists = fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`);
    if (!tunnelExists && !tunnelWasObserved && Date.now() < startupDeadline) {
      continue;
    }
    try {
      await runTunnelHealthcheck(false);
    } catch (error) {
      await stopProxyProcesses("tunnel-health-lost");
      if (!tunnelWasObserved && Date.now() < startupDeadline) {
        log("debug", "watchdog.startup.pending", { error: error.message });
        continue;
      }
      consecutiveFailures += 1;
      log("warn", "watchdog.check.failed", {
        consecutiveFailures,
        error: error.message,
      });
      if (consecutiveFailures >= WATCHDOG_FAILURE_THRESHOLD) {
        log("error", "watchdog.reconnect.triggered", { consecutiveFailures });
        openConnectProcess.kill("SIGTERM");
        break;
      }
      continue;
    }
    tunnelWasObserved = true;
    consecutiveFailures = 0;
    if (shutdownRequested || !isProcessRunning(openConnectProcess)) {
      break;
    }
    try {
      await ensureProxyProcessesRunning();
      await runProxyEgressHealthcheck(false);
    } catch (error) {
      await stopProxyProcesses("proxy-egress-failed");
      log("error", "watchdog.proxy.failed", { error: error.message });
    }
  }
  log("info", "watchdog.stop");
}

function runOpenConnect() {
  log("info", "openconnect.start.enter", { server: VPN_SERVER });
  const openConnectArguments = [
    "--protocol=anyconnect",
    "--external-browser=/app/vpn.js",
    `--interface=${TUNNEL_INTERFACE}`,
    "--script=/app/vpnc-script",
    "--os=linux-64",
    "--useragent=AnyConnect Linux_64 5.1.11.388",
    "--version-string=5.1.11.388",
    "--timestamp",
    "--verbose",
    "--reconnect-timeout=300",
    VPN_SERVER,
  ];
  const openConnectProcess = spawn("openconnect", openConnectArguments, {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  activeOpenConnectProcess = openConnectProcess;
  streamProcessLines(
    openConnectProcess.stdout,
    "openconnect",
    "stdout",
    sanitizeOpenConnectLine,
  );
  streamProcessLines(
    openConnectProcess.stderr,
    "openconnect",
    "stderr",
    sanitizeOpenConnectLine,
  );
  monitorTunnel(openConnectProcess).catch((error) => {
    log("error", "watchdog.fatal", { error: error.message });
    void stopProxyProcesses("watchdog-fatal").catch((stopError) => {
      shutdownRequested = true;
      log("error", "watchdog.proxy_stop.fatal", { error: stopError.message });
    });
    if (isProcessRunning(openConnectProcess)) {
      openConnectProcess.kill("SIGTERM");
    }
  });
  return new Promise((resolve, reject) => {
    openConnectProcess.once("error", reject);
    openConnectProcess.once("exit", async (code, signal) => {
      log("warn", "openconnect.start.exit", { code, signal });
      activeOpenConnectProcess = null;
      try {
        await stopProxyProcesses("openconnect-exited");
        resolve(code === null ? 1 : code);
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function connectForever() {
  validateVpnServer();
  readCredentials();
  writeStaticResolverConfiguration();
  await configureProxyKillSwitch();
  await captureOriginalPublicIp();
  while (!shutdownRequested) {
    const exitCode = await runOpenConnect();
    if (shutdownRequested) {
      break;
    }
    log("warn", "openconnect.restart.scheduled", { exitCode, delaySeconds: 5 });
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
}

async function runTunnelHealthcheck(emitSuccess = true) {
  if (!fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)) {
    throw new Error(`Tunnel interface ${TUNNEL_INTERFACE} is absent`);
  }
  const originalPublicIp = fs.readFileSync(ORIGINAL_PUBLIC_IP_FILE, "utf8").trim();
  if (!net.isIP(originalPublicIp)) {
    throw new Error("Original public IP state is invalid");
  }
  const currentPublicIp = await fetchPublicIp();
  assertVpnPublicIp(currentPublicIp, originalPublicIp, "direct");
  if (emitSuccess) {
    process.stdout.write("healthy: public IP differs from the pre-VPN public IP\n");
  }
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
    throw new Error(`${requestLabel} egress returned the pre-VPN public IP`);
  }
}

async function runProxyEgressHealthcheck(emitSuccess = true) {
  const originalPublicIp = readOriginalPublicIp();
  const [httpPublicIp, socksPublicIp] = await Promise.all([
    fetchPublicIp(`http://127.0.0.1:${HTTP_PROXY_PORT}`, "HTTP proxy"),
    fetchPublicIp(`socks5h://127.0.0.1:${SOCKS_PROXY_PORT}`, "SOCKS5 proxy"),
  ]);
  assertVpnPublicIp(httpPublicIp, originalPublicIp, "HTTP proxy");
  assertVpnPublicIp(socksPublicIp, originalPublicIp, "SOCKS5 proxy");
  if (emitSuccess) {
    process.stdout.write("healthy: HTTP/SOCKS proxy egress differs from the pre-VPN public IP\n");
  }
}

async function runHealthcheck(emitSuccess = true) {
  if (!fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)) {
    throw new Error(`Tunnel interface ${TUNNEL_INTERFACE} is absent`);
  }
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
  ["SIGINT", "SIGTERM"].forEach((signalName) => {
    process.on(signalName, () => {
      shutdownRequested = true;
      log("warn", "shutdown.requested", { signal: signalName });
      void stopProxyProcesses("shutdown-requested").catch((error) => {
        log("error", "shutdown.proxy_stop.failed", { error: error.message });
      });
      if (activeOpenConnectProcess) {
        activeOpenConnectProcess.kill("SIGTERM");
      }
    });
  });
}

async function main() {
  installSignalHandlers();
  const command = process.argv[2] || "connect";
  if (/^https?:\/\//i.test(command)) {
    await runBrowser(command);
    return;
  }
  if (command === "connect") {
    await connectForever();
    return;
  }
  if (command === "healthcheck") {
    await runHealthcheck();
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
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  log("error", "fatal", { error: error.message });
  process.exit(1);
});
