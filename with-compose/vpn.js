#!/usr/bin/env node

/*
 * Autonomous AnyConnect VPN sidecar. OpenConnect owns Cisco's encrypted SSO
 * callback while Playwright supplies credentials and RFC 6238 MFA.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const process = require("node:process");
const { spawn } = require("node:child_process");
const { chromium } = require("playwright");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BROWSER_HEADLESS = !["0", "false", "no"].includes(
  String(process.env.VPN_BROWSER_HEADLESS || "true").toLowerCase(),
);
const BROWSER_PROFILE_DIRECTORY = process.env.VPN_BROWSER_PROFILE_DIRECTORY
  || "/tmp/vpn-browser-profile";
const BROWSER_TIMEOUT_MILLISECONDS = Number(
  process.env.VPN_BROWSER_TIMEOUT_MILLISECONDS || 180000,
);
const ORIGINAL_PUBLIC_IP_FILE = process.env.VPN_ORIGINAL_PUBLIC_IP_FILE
  || "/run/vpn-sidecar/original-public-ip";
const PUBLIC_IP_ENDPOINT = process.env.VPN_PUBLIC_IP_ENDPOINT
  || "https://ifconfig.io/ip";
const RUNTIME_DIRECTORY = path.dirname(ORIGINAL_PUBLIC_IP_FILE);
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
let shutdownRequested = false;

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

async function fetchPublicIp() {
  log("debug", "public_ip.fetch.enter", {
    endpoint: new URL(PUBLIC_IP_ENDPOINT).hostname,
  });
  const curlArguments = [
    "--fail",
    "--silent",
    "--show-error",
    "--max-time",
    "7",
    PUBLIC_IP_ENDPOINT,
  ];
  const curlResult = await new Promise((resolve, reject) => {
    const curlProcess = spawn("curl", curlArguments, { stdio: ["ignore", "pipe", "pipe"] });
    const stdoutChunks = [];
    const stderrChunks = [];
    curlProcess.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    curlProcess.stderr.on("data", (chunk) => stderrChunks.push(chunk));
    curlProcess.once("error", reject);
    curlProcess.once("exit", (code) => resolve({ code, stderrChunks, stdoutChunks }));
  });
  if (curlResult.code !== 0) {
    const errorMessage = Buffer.concat(curlResult.stderrChunks).toString("utf8").trim();
    throw new Error(`curl ifconfig.io failed with code ${curlResult.code}: ${errorMessage}`);
  }
  const candidateIp = Buffer.concat(curlResult.stdoutChunks).toString("utf8").trim();
  if (!net.isIP(candidateIp)) {
    throw new Error("curl ifconfig.io returned an invalid public IP address");
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
  await locator.click();
  log("info", "browser.control.clicked", { control: actionName });
  return true;
}

async function clickFirstMatchingText(page, patterns, actionName) {
  for (const pattern of patterns) {
    const locator = page.getByText(pattern, { exact: false }).first();
    if (await locator.count() && await locator.isVisible()) {
      await locator.click();
      log("info", "browser.control.clicked", { control: actionName });
      return true;
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

function streamSanitizedLines(stream, streamName) {
  let bufferedText = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    bufferedText += chunk;
    const lines = bufferedText.split(/\r?\n/);
    bufferedText = lines.pop() || "";
    lines.filter(Boolean).forEach((line) => {
      log("info", "openconnect.output", {
        stream: streamName,
        message: sanitizeOpenConnectLine(line),
      });
    });
  });
  stream.on("end", () => {
    if (bufferedText) {
      log("info", "openconnect.output", {
        stream: streamName,
        message: sanitizeOpenConnectLine(bufferedText),
      });
    }
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
  while (!shutdownRequested && openConnectProcess.exitCode === null) {
    await new Promise((resolve) => setTimeout(resolve, WATCHDOG_INTERVAL_MILLISECONDS));
    if (shutdownRequested || openConnectProcess.exitCode !== null) {
      break;
    }
    const tunnelExists = fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`);
    if (!tunnelExists && !tunnelWasObserved && Date.now() < startupDeadline) {
      continue;
    }
    try {
      await runHealthcheck(false);
      tunnelWasObserved = true;
      consecutiveFailures = 0;
    } catch (error) {
      consecutiveFailures += 1;
      log("warn", "watchdog.check.failed", {
        consecutiveFailures,
        error: error.message,
      });
    }
    if (consecutiveFailures >= WATCHDOG_FAILURE_THRESHOLD) {
      log("error", "watchdog.reconnect.triggered", { consecutiveFailures });
      openConnectProcess.kill("SIGTERM");
      break;
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
  streamSanitizedLines(openConnectProcess.stdout, "stdout");
  streamSanitizedLines(openConnectProcess.stderr, "stderr");
  monitorTunnel(openConnectProcess).catch((error) => {
    log("error", "watchdog.fatal", { error: error.message });
    if (openConnectProcess.exitCode === null) {
      openConnectProcess.kill("SIGTERM");
    }
  });
  return new Promise((resolve, reject) => {
    openConnectProcess.once("error", reject);
    openConnectProcess.once("exit", (code, signal) => {
      log("warn", "openconnect.start.exit", { code, signal });
      activeOpenConnectProcess = null;
      resolve(code === null ? 1 : code);
    });
  });
}

async function connectForever() {
  validateVpnServer();
  readCredentials();
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

async function runHealthcheck(emitSuccess = true) {
  if (!fs.existsSync(`/sys/class/net/${TUNNEL_INTERFACE}`)) {
    throw new Error(`Tunnel interface ${TUNNEL_INTERFACE} is absent`);
  }
  const originalPublicIp = fs.readFileSync(ORIGINAL_PUBLIC_IP_FILE, "utf8").trim();
  if (!net.isIP(originalPublicIp)) {
    throw new Error("Original public IP state is invalid");
  }
  const currentPublicIp = await fetchPublicIp();
  if (currentPublicIp === originalPublicIp) {
    throw new Error("The public IP endpoint still returns the pre-VPN public IP");
  }
  if (emitSuccess) {
    process.stdout.write("healthy: public IP differs from the pre-VPN public IP\n");
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
  await fetchPublicIp();
  process.stdout.write(
    "self-test passed: environment credentials, RFC 6238 TOTP, and curl verified\n",
  );
}

function installSignalHandlers() {
  ["SIGINT", "SIGTERM"].forEach((signalName) => {
    process.on(signalName, () => {
      shutdownRequested = true;
      log("warn", "shutdown.requested", { signal: signalName });
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
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  log("error", "fatal", { error: error.message });
  process.exitCode = 1;
});
