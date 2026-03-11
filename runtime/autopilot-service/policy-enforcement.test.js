#!/usr/bin/env node
/**
 * Policy Enforcement Tests — time_windows, rate_limits, idempotency
 */

const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs").promises;
const path = require("path");
const os = require("os");

// Set test environment
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `autopilot-policy-test-${Date.now()}`);

const {
  loadPolicyConfig,
  policyCheckAction,
  policyCheckTimeWindow,
  policyCheckActionRateLimit,
  policyCheckIdempotency,
  recordActionExecution,
  recordActionForDedup,
  resetActionRateLimitState,
  resetDeduplicationState,
} = require("./index.js");

// ============================================================================
// TIME WINDOW ENFORCEMENT
// ============================================================================

describe("Policy Enforcement - policyCheckTimeWindow", () => {
  afterEach(() => {
    resetActionRateLimitState();
    resetDeduplicationState();
  });

  it("allows when no policy is loaded (bootstrap mode)", () => {
    const result = policyCheckTimeWindow("action_execution");
    assert.strictEqual(result.allowed, true);
  });

  it("allows when time_windows.enabled is false", async () => {
    const tmpDir = path.join(os.tmpdir(), `tw-disabled-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
time_windows:
  enabled: false
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckTimeWindow("action_execution");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("disabled"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows when operation is within the configured time window", async () => {
    const tmpDir = path.join(os.tmpdir(), `tw-within-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    // Build a policy that always matches — all days, 00:00-23:59
    const dayNames = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
time_windows:
  enabled: true
  operations:
    action_execution:
      windows:
        - days: [${dayNames.join(", ")}]
          start: "00:00"
          end: "23:59"
          timezone: UTC
      outside_window_action: deny
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckTimeWindow("action_execution");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("Within"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("denies when operation is outside the configured time window", async () => {
    const tmpDir = path.join(os.tmpdir(), `tw-outside-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    // Empty days list — no day will match, so always outside window
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
time_windows:
  enabled: true
  operations:
    action_execution:
      windows:
        - days: []
          start: "00:00"
          end: "23:59"
          timezone: UTC
      outside_window_action: deny
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckTimeWindow("action_execution");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("Outside"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows outside window when outside_window_action is 'allow'", async () => {
    const tmpDir = path.join(os.tmpdir(), `tw-allow-outside-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
time_windows:
  enabled: true
  operations:
    response_planning:
      windows:
        - days: []
          start: "00:00"
          end: "23:59"
          timezone: UTC
      outside_window_action: allow
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckTimeWindow("response_planning");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("outside_window_action=allow"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows for unknown operation types (not in policy)", async () => {
    const tmpDir = path.join(os.tmpdir(), `tw-unknown-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
time_windows:
  enabled: true
  operations:
    action_execution:
      windows:
        - days: []
      outside_window_action: deny
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckTimeWindow("nonexistent_op");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("No time window configured"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// RATE LIMIT ENFORCEMENT
// ============================================================================

describe("Policy Enforcement - policyCheckActionRateLimit", () => {
  afterEach(() => {
    resetActionRateLimitState();
    resetDeduplicationState();
  });

  it("allows when no policy is loaded (bootstrap mode)", () => {
    const result = policyCheckActionRateLimit("block_ip");
    assert.strictEqual(result.allowed, true);
  });

  it("allows when no rate limits are configured", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-none-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
actions:
  enabled: true
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckActionRateLimit("block_ip");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("No rate limits"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows when under the rate limit", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-under-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  actions:
    block_ip:
      max_per_hour: 10
      max_per_day: 100
  global:
    max_actions_per_hour: 200
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      // Record a few executions
      recordActionExecution("block_ip");
      recordActionExecution("block_ip");

      const result = policyCheckActionRateLimit("block_ip");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("denies when hourly per-action rate limit is exceeded", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-hourly-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  actions:
    block_ip:
      max_per_hour: 3
      max_per_day: 100
  global:
    max_actions_per_hour: 200
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionExecution("block_ip");
      recordActionExecution("block_ip");
      recordActionExecution("block_ip");

      const result = policyCheckActionRateLimit("block_ip");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("hourly rate limit"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("denies when daily per-action rate limit is exceeded", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-daily-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  actions:
    isolate_host:
      max_per_hour: 100
      max_per_day: 2
  global:
    max_actions_per_hour: 200
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionExecution("isolate_host");
      recordActionExecution("isolate_host");

      const result = policyCheckActionRateLimit("isolate_host");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("daily rate limit"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("denies when global hourly rate limit is exceeded", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-global-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  global:
    max_actions_per_hour: 3
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionExecution("block_ip");
      recordActionExecution("isolate_host");
      recordActionExecution("kill_process");

      const result = policyCheckActionRateLimit("disable_user");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("Global hourly"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows actions with no specific rate limit when global limit is OK", async () => {
    const tmpDir = path.join(os.tmpdir(), `rl-unlisted-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  actions:
    block_ip:
      max_per_hour: 10
      max_per_day: 100
  global:
    max_actions_per_hour: 200
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      // "custom_action" is not in the rate_limits.actions list
      const result = policyCheckActionRateLimit("custom_action");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// IDEMPOTENCY / DUPLICATE DETECTION
// ============================================================================

describe("Policy Enforcement - policyCheckIdempotency", () => {
  afterEach(() => {
    resetActionRateLimitState();
    resetDeduplicationState();
  });

  it("allows when no policy is loaded (bootstrap mode)", () => {
    const result = policyCheckIdempotency("block_ip", "10.0.0.1");
    assert.strictEqual(result.allowed, true);
  });

  it("allows when idempotency is disabled", async () => {
    const tmpDir = path.join(os.tmpdir(), `idemp-disabled-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: false
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("disabled"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows first execution of an action+target", async () => {
    const tmpDir = path.join(os.tmpdir(), `idemp-first-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: true
  duplicate_detection:
    enabled: true
    window_minutes: 60
    deny_reason: DUPLICATE_REQUEST
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, true);
      assert.ok(result.reason.includes("passed"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("denies duplicate action+target within window", async () => {
    const tmpDir = path.join(os.tmpdir(), `idemp-dup-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: true
  duplicate_detection:
    enabled: true
    window_minutes: 60
    deny_reason: DUPLICATE_REQUEST
`);
    try {
      await loadPolicyConfig(tmpDir);
      // Record first execution
      recordActionForDedup("block_ip", "10.0.0.1");
      // Now check — should be denied
      const result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("DUPLICATE_REQUEST"));
      assert.ok(result.reason.includes("block_ip"));
      assert.ok(result.reason.includes("10.0.0.1"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows same action on a different target", async () => {
    const tmpDir = path.join(os.tmpdir(), `idemp-difftarget-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: true
  duplicate_detection:
    enabled: true
    window_minutes: 60
    deny_reason: DUPLICATE_REQUEST
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionForDedup("block_ip", "10.0.0.1");
      // Different target — should be allowed
      const result = policyCheckIdempotency("block_ip", "10.0.0.2");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows when duplicate_detection is not enabled", async () => {
    const tmpDir = path.join(os.tmpdir(), `idemp-dd-off-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: true
  duplicate_detection:
    enabled: false
    window_minutes: 60
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionForDedup("block_ip", "10.0.0.1");
      const result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// RECORDING AND RESET HELPERS
// ============================================================================

describe("Policy Enforcement - recording and reset helpers", () => {
  afterEach(() => {
    resetActionRateLimitState();
    resetDeduplicationState();
  });

  it("resetActionRateLimitState clears all rate limit counters", async () => {
    const tmpDir = path.join(os.tmpdir(), `reset-rl-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
rate_limits:
  actions:
    block_ip:
      max_per_hour: 2
      max_per_day: 10
  global:
    max_actions_per_hour: 200
    max_actions_per_day: 1000
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionExecution("block_ip");
      recordActionExecution("block_ip");

      // Should be denied — limit of 2
      let result = policyCheckActionRateLimit("block_ip");
      assert.strictEqual(result.allowed, false);

      // Reset
      resetActionRateLimitState();

      // Should be allowed again
      result = policyCheckActionRateLimit("block_ip");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("resetDeduplicationState clears dedup entries", async () => {
    const tmpDir = path.join(os.tmpdir(), `reset-dedup-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });
    await fs.writeFile(path.join(policyDir, "policy.yaml"), `
idempotency:
  enabled: true
  duplicate_detection:
    enabled: true
    window_minutes: 60
    deny_reason: DUPLICATE_REQUEST
`);
    try {
      await loadPolicyConfig(tmpDir);
      recordActionForDedup("block_ip", "10.0.0.1");

      let result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, false);

      resetDeduplicationState();

      result = policyCheckIdempotency("block_ip", "10.0.0.1");
      assert.strictEqual(result.allowed, true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// policyCheckAction — min_confidence enforcement
// ============================================================================

describe("Policy Enforcement - policyCheckAction min_confidence", () => {
  it("denies action when confidence is 0 (unknown) and min_confidence is configured", async () => {
    const tmpDir = path.join(os.tmpdir(), `autopilot-confidence-test-${Date.now()}`);
    await fs.mkdir(path.join(tmpDir, "policies"), { recursive: true });
    await fs.writeFile(path.join(tmpDir, "policies", "policy.yaml"), `
actions:
  enabled: true
  deny_unlisted: false
  allowlist:
    block_ip:
      enabled: true
      min_confidence: 0.7
`);
    try {
      await loadPolicyConfig(tmpDir);

      // Confidence 0 (unknown) should be denied when min_confidence is set
      const result = policyCheckAction("block_ip", 0);
      assert.strictEqual(result.allowed, false, "confidence=0 should be denied when min_confidence=0.7");
      assert.ok(result.reason.includes("below minimum"));

      // Confidence above threshold should be allowed
      const allowed = policyCheckAction("block_ip", 0.85);
      assert.strictEqual(allowed.allowed, true);

      // Confidence below threshold should be denied
      const denied = policyCheckAction("block_ip", 0.5);
      assert.strictEqual(denied.allowed, false);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows action when no min_confidence is configured", async () => {
    const tmpDir = path.join(os.tmpdir(), `autopilot-noconf-test-${Date.now()}`);
    await fs.mkdir(path.join(tmpDir, "policies"), { recursive: true });
    await fs.writeFile(path.join(tmpDir, "policies", "policy.yaml"), `
actions:
  enabled: true
  deny_unlisted: false
  allowlist:
    block_ip:
      enabled: true
`);
    try {
      await loadPolicyConfig(tmpDir);
      const result = policyCheckAction("block_ip", 0);
      assert.strictEqual(result.allowed, true, "confidence=0 should be allowed when no min_confidence");
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
