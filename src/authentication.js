// authentication responsibilities for the VPN proxy.
"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");

const runtimeState = require("./state");
const {
  BASE32_ALPHABET,
  BROWSER_PROFILE_DIRECTORY,
  BROWSER_TIMEOUT_MILLISECONDS,
} = require("./config");
const { log } = require("./runtime");

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
    if (!runtimeState.playwrightErrors || !(error instanceof runtimeState.playwrightErrors.TimeoutError)) {
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
  const passwordSelectors = [
    'input[name="passwd"]:not([aria-hidden="true"])',
    'input[type="password"]:not([aria-hidden="true"])',
  ];
  if (await firstVisibleLocator(page, passwordSelectors)) {
    if (state.lastAction === "password") {
      return false;
    }
    await fillAndPressEnter(
      page,
      passwordSelectors,
      credentials.password,
      "password",
    );
    state.lastAction = "password";
    return true;
  }
  const usernameSelectors = [
    'input[name="loginfmt"]:not([aria-hidden="true"])',
    'input[type="email"]:not([aria-hidden="true"])',
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
    location: safeLocation(startUrl),
  });
  const credentials = readCredentials();
  const { chromium, errors } = require("playwright");
  runtimeState.playwrightErrors = errors;
  fs.mkdirSync(BROWSER_PROFILE_DIRECTORY, { mode: 0o700, recursive: true });
  const browserContext = await chromium.launchPersistentContext(
    BROWSER_PROFILE_DIRECTORY,
    {
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
      headless: true,
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
        callbackObserved = response.status() >= 200 && response.status() < 400;
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

module.exports = {
  readCredentials,
  normalizeTotpSecret,
  decodeBase32,
  generateTotp,
  safeLocation,
  sanitizeAuthenticationMessage,
  firstVisibleLocator,
  firstVisibleText,
  fillFirstVisible,
  fillAndPressEnter,
  clickFirstVisible,
  clickLocator,
  clickFirstMatchingText,
  submitCurrentForm,
  handleRememberedAccount,
  handleCredentialForm,
  handleTotpForm,
  handleMfaChoice,
  isStaySignedInPage,
  handlePostAuthenticationPage,
  detectAuthenticationError,
  driveAuthenticationPage,
  runBrowser,
};
