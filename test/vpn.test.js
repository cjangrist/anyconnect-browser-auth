const assert = require("node:assert/strict");
const test = require("node:test");

const { generateTotp } = require("../src/vpn");

test("generates the RFC 6238 SHA-1 test vector", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(generateTotp(secret, 59000, 8), "94287082");
});
