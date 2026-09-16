// runtime responsibilities for the VPN proxy.
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { COLORS } = require("./config");

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

function runCommand(command, argumentsList, input = "", timeoutMilliseconds = 15000) {
  return new Promise((resolve, reject) => {
    const commandProcess = spawn(command, argumentsList, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timeout = setTimeout(() => {
      commandProcess.kill("SIGKILL");
      reject(new Error(`${command} exceeded ${timeoutMilliseconds}ms`));
    }, timeoutMilliseconds);
    commandProcess.stdin.on("error", () => {});
    commandProcess.stdin.end(input);
    const stdoutChunks = [];
    const stderrChunks = [];
    commandProcess.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    commandProcess.stderr.on("data", (chunk) => stderrChunks.push(chunk));
    let settled = false;
    commandProcess.once("error", (error) => {
      clearTimeout(timeout);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    commandProcess.once("close", (code) => {
      clearTimeout(timeout);
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
  return Boolean(childProcess?.pid)
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
      childProcess.removeListener("exit", onExit);
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
    const onExit = () => complete();
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
    childProcess.once("exit", onExit);
    if (!isProcessRunning(childProcess)) complete();
  });
}

function writeAtomicState(filename, content) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temporaryPath = `${filename}.${process.pid}.new`;
  fs.writeFileSync(temporaryPath, content, { mode: 0o600 });
  fs.renameSync(temporaryPath, filename);
}

module.exports = {
  writeAtomicState,
  log,
  runCommand,
  isProcessRunning,
  requireCommandSuccess,
  resolveSystemUserId,
  resolveSystemGroupId,
  streamProcessLines,
  waitForProcessExit,
};
