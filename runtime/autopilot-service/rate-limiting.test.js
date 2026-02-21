/**
 * Rate limiting and auth failure lockout tests.
 *
 * Uses Node.js built-in test runner -- no external dependencies.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");

// Set env vars BEFORE requiring index.js (module reads them at load time)
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `rate-test-${Date.now()}`);
process.env.RATE_LIMIT_MAX_REQUESTS = "5";
process.env.RATE_LIMIT_WINDOW_MS = "2000";
process.env.AUTH_FAILURE_MAX_ATTEMPTS = "3";
process.env.AUTH_FAILURE_WINDOW_MS = "5000";
process.env.AUTH_LOCKOUT_DURATION_MS = "2000";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");

const {
  checkRateLimit,
  recordAuthFailure,
  isAuthLocked,
  clearAuthFailures,
} = require("./index.js");

const dataDir = process.env.AUTOPILOT_DATA_DIR;

describe("Rate Limiting", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("first request is allowed with correct remaining count", () => {
    const result = checkRateLimit("10.0.0.1");
    assert.equal(result.allowed, true);
    assert.equal(result.remaining, 4); // max (5) - 1
  });

  it("requests within limit are all allowed", () => {
    const ip = "10.0.0.2";
    for (let i = 0; i < 4; i++) {
      const result = checkRateLimit(ip);
      assert.equal(result.allowed, true);
    }
  });

  it("request at limit returns allowed false", () => {
    const ip = "10.0.0.3";
    // Consume all 5 allowed requests
    for (let i = 0; i < 5; i++) {
      checkRateLimit(ip);
    }
    // 6th request should be blocked
    const result = checkRateLimit(ip);
    assert.equal(result.allowed, false);
    assert.equal(result.remaining, 0);
  });

  it("different IPs have independent limits", () => {
    const ipA = "10.1.1.1";
    const ipB = "10.1.1.2";

    // Exhaust limit for IP A
    for (let i = 0; i < 5; i++) {
      checkRateLimit(ipA);
    }
    const blockedA = checkRateLimit(ipA);
    assert.equal(blockedA.allowed, false);

    // IP B should still be allowed
    const resultB = checkRateLimit(ipB);
    assert.equal(resultB.allowed, true);
  });

  it("rate limit retryAfter is a positive number", () => {
    const ip = "10.2.0.1";
    for (let i = 0; i < 5; i++) {
      checkRateLimit(ip);
    }
    const result = checkRateLimit(ip);
    assert.equal(result.allowed, false);
    assert.equal(typeof result.retryAfter, "number");
    assert.ok(result.retryAfter > 0, "retryAfter should be positive");
  });
});

describe("Auth Failure Lockout", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("auth failure recording returns correct attempts remaining", () => {
    const ip = "10.3.0.1";
    clearAuthFailures(ip);
    // First failure starts a new window -- returns { locked: false } (no attemptsRemaining on first)
    recordAuthFailure(ip);
    // Second failure should show attemptsRemaining
    const result = recordAuthFailure(ip);
    assert.equal(result.locked, false);
    assert.equal(result.attemptsRemaining, 1); // 3 max - 2 used = 1
  });

  it("auth lockout triggers after max failures", () => {
    const ip = "10.3.0.2";
    clearAuthFailures(ip);
    recordAuthFailure(ip); // 1
    recordAuthFailure(ip); // 2
    const result = recordAuthFailure(ip); // 3 -- should lock
    assert.equal(result.locked, true);
    assert.equal(typeof result.retryAfter, "number");
    assert.ok(result.retryAfter > 0);
  });

  it("isAuthLocked returns true when locked", () => {
    const ip = "10.3.0.3";
    clearAuthFailures(ip);
    recordAuthFailure(ip);
    recordAuthFailure(ip);
    recordAuthFailure(ip); // triggers lockout
    const result = isAuthLocked(ip);
    assert.equal(result.locked, true);
    assert.equal(typeof result.retryAfter, "number");
  });

  it("isAuthLocked returns false when not locked", () => {
    const ip = "10.3.0.4";
    clearAuthFailures(ip);
    const result = isAuthLocked(ip);
    assert.equal(result.locked, false);
  });

  it("clearAuthFailures resets state", () => {
    const ip = "10.3.0.5";
    clearAuthFailures(ip);
    recordAuthFailure(ip);
    recordAuthFailure(ip);
    recordAuthFailure(ip); // locked
    assert.equal(isAuthLocked(ip).locked, true);

    clearAuthFailures(ip);
    assert.equal(isAuthLocked(ip).locked, false);
  });

  it("auth lockout for different IPs is independent", () => {
    const ipA = "10.4.0.1";
    const ipB = "10.4.0.2";
    clearAuthFailures(ipA);
    clearAuthFailures(ipB);

    // Lock IP A
    recordAuthFailure(ipA);
    recordAuthFailure(ipA);
    recordAuthFailure(ipA);
    assert.equal(isAuthLocked(ipA).locked, true);

    // IP B should not be locked
    assert.equal(isAuthLocked(ipB).locked, false);
  });

  it("auth failure returns locked true at exactly max attempts", () => {
    const ip = "10.5.0.1";
    clearAuthFailures(ip);

    let result;
    // Record exactly AUTH_FAILURE_MAX_ATTEMPTS (3) failures
    result = recordAuthFailure(ip); // 1st -- starts window
    assert.equal(result.locked, false);

    result = recordAuthFailure(ip); // 2nd
    assert.equal(result.locked, false);

    result = recordAuthFailure(ip); // 3rd -- exactly at max
    assert.equal(result.locked, true);
  });
});
