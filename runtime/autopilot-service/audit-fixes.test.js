/**
 * Tests for the production-readiness audit fixes:
 *  - ipMatchesEntry (IPv4 / CIDR matcher)
 *  - policyCheckProtectedTarget (protected-target deny-list)
 *  - policyCheckSlackContext (Slack workspace/channel allowlist, placeholder-aware)
 *  - verifyActionExecution (no-config null path)
 *  - autoCloseExecutedCases (does not throw on empty store)
 *  - /api/reports type whitelist (path-traversal guard, Issue H2)
 *
 * Run:  node --test audit-fixes.test.js
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const os = require("os");
const path = require("path");

const TEST_DATA_DIR = path.join(os.tmpdir(), `autopilot-audit-test-${Date.now()}-${process.pid}`);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
process.env.AUTOPILOT_CONFIG_DIR = REPO_ROOT; // so loadPolicyConfig reads the real policy.yaml
process.env.AUTOPILOT_MCP_AUTH = "test-mcp-secret-token";
process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-token";
process.env.LOG_LEVEL = "error";

const idx = require("./index");

function request(server, method, urlPath) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const req = http.request(
      { hostname: "127.0.0.1", port: addr.port, path: urlPath, method },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          let body;
          try { body = JSON.parse(raw); } catch { body = raw; }
          resolve({ status: res.statusCode, body, raw });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("ipMatchesEntry", () => {
  it("matches exact IPv4", () => {
    assert.equal(idx.ipMatchesEntry("10.0.0.1", "10.0.0.1"), true);
    assert.equal(idx.ipMatchesEntry("10.0.0.2", "10.0.0.1"), false);
  });
  it("matches inside a CIDR range", () => {
    assert.equal(idx.ipMatchesEntry("10.0.0.7", "10.0.0.0/24"), true);
    assert.equal(idx.ipMatchesEntry("10.0.1.7", "10.0.0.0/24"), false);
    assert.equal(idx.ipMatchesEntry("127.0.0.9", "127.0.0.0/8"), true);
  });
  it("handles /0 and /32 boundaries", () => {
    assert.equal(idx.ipMatchesEntry("203.0.113.5", "0.0.0.0/0"), true);
    assert.equal(idx.ipMatchesEntry("203.0.113.5", "203.0.113.5/32"), true);
    assert.equal(idx.ipMatchesEntry("203.0.113.6", "203.0.113.5/32"), false);
  });
  it("rejects malformed input safely", () => {
    assert.equal(idx.ipMatchesEntry("not-an-ip", "10.0.0.0/24"), false);
    assert.equal(idx.ipMatchesEntry("10.0.0.1", "garbage"), false);
  });
});

describe("policyCheckProtectedTarget", () => {
  before(async () => { await idx.loadPolicyConfig(REPO_ROOT); });

  it("blocks loopback for block_ip (default deny-list 127.0.0.0/8)", () => {
    const r = idx.policyCheckProtectedTarget({ type: "block_ip", target: "127.0.0.5" });
    assert.equal(r.allowed, false);
    assert.match(r.reason, /protected-targets deny-list/);
  });
  it("allows a normal public IP", () => {
    assert.equal(idx.policyCheckProtectedTarget({ type: "block_ip", target: "203.0.113.10" }).allowed, true);
  });
  it("checks params.src_ip for firewall_drop / host_deny", () => {
    assert.equal(idx.policyCheckProtectedTarget({ type: "firewall_drop", target: "002", params: { src_ip: "127.9.9.9" } }).allowed, false);
    assert.equal(idx.policyCheckProtectedTarget({ type: "host_deny", target: "002", params: { src_ip: "203.0.113.1" } }).allowed, true);
  });
  it("protects agent 000 for isolate_host / restart_wazuh", () => {
    assert.equal(idx.policyCheckProtectedTarget({ type: "isolate_host", params: { agent_id: "000" } }).allowed, false);
    assert.equal(idx.policyCheckProtectedTarget({ type: "isolate_host", params: { agent_id: "002" } }).allowed, true);
  });
  it("ignores non-targeted action types", () => {
    assert.equal(idx.policyCheckProtectedTarget({ type: "kill_process", params: { agent_id: "000", process_id: 1 } }).allowed, true);
  });
});

describe("policyCheckSlackContext", () => {
  before(async () => { await idx.loadPolicyConfig(REPO_ROOT); });
  it("allows when allowlists are still placeholders (bootstrap-safe)", () => {
    // Default policy.yaml ships <PLACEHOLDER> ids, so context checks must not block.
    assert.equal(idx.policyCheckSlackContext("T123", "C123", "commands").allowed, true);
  });
});

describe("verifyActionExecution", () => {
  it("returns null when the action type has no verification config", async () => {
    const r = await idx.verifyActionExecution({ type: "does_not_exist", target: "x" }, {}, "corr-1");
    assert.equal(r, null);
  });
});

describe("autoCloseExecutedCases", () => {
  it("does not throw on an empty case store", async () => {
    await assert.doesNotReject(() => idx.autoCloseExecutedCases());
  });
});

describe("/api/reports type whitelist (path-traversal guard)", () => {
  let server;
  before(async () => {
    server = idx.createServer();
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
  });
  after(() => new Promise((r) => server.close(r)));

  it("rejects a traversal type with 400", async () => {
    const res = await request(server, "GET", `/api/reports?type=${encodeURIComponent("../../etc")}&token=test-service-token`);
    assert.equal(res.status, 400);
  });
  it("accepts a valid type", async () => {
    const res = await request(server, "GET", "/api/reports?type=daily&token=test-service-token");
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body));
  });
});
