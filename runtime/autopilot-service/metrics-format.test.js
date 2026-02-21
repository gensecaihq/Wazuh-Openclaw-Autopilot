/**
 * Metrics formatting and sanitization tests.
 *
 * Uses Node.js built-in test runner -- no external dependencies.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");

// Set env vars BEFORE requiring index.js
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `metrics-test-${Date.now()}`);

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");

const {
  incrementMetric,
  recordLatency,
  formatMetrics,
  sanitizeMetricLabelName,
} = require("./index.js");

const dataDir = process.env.AUTOPILOT_DATA_DIR;

describe("sanitizeMetricLabelName", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("replaces special characters with underscore", () => {
    assert.equal(sanitizeMetricLabelName("host-name.example"), "host_name_example");
    assert.equal(sanitizeMetricLabelName("foo@bar!baz"), "foo_bar_baz");
    assert.equal(sanitizeMetricLabelName("key with spaces"), "key_with_spaces");
  });

  it("preserves valid alphanumeric and underscore characters", () => {
    assert.equal(sanitizeMetricLabelName("valid_name_123"), "valid_name_123");
    assert.equal(sanitizeMetricLabelName("abc"), "abc");
    assert.equal(sanitizeMetricLabelName("A_Z_0"), "A_Z_0");
  });

  it("handles empty string", () => {
    assert.equal(sanitizeMetricLabelName(""), "");
  });
});

describe("Metrics collection and formatting", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("incrementMetric increments counter visible in formatMetrics", () => {
    // Increment a simple counter several times
    incrementMetric("cases_created_total");
    incrementMetric("cases_created_total");

    const output = formatMetrics();
    // The output should contain the metric name with a non-zero value
    assert.ok(
      output.includes("autopilot_cases_created_total"),
      "formatMetrics output should include autopilot_cases_created_total",
    );
  });

  it("incrementMetric with labels creates labeled metric", () => {
    incrementMetric("mcp_tool_calls_total", { tool: "wazuh_get_alert" });
    incrementMetric("mcp_tool_calls_total", { tool: "wazuh_get_alert" });

    const output = formatMetrics();
    assert.ok(
      output.includes("wazuh_get_alert"),
      "formatMetrics output should include the label value",
    );
    assert.ok(
      output.includes("autopilot_mcp_tool_calls_total"),
      "formatMetrics output should include the labeled counter name",
    );
  });

  it("recordLatency records value visible in formatMetrics as sum and count", () => {
    recordLatency("triage_latency_seconds", 0.5);
    recordLatency("triage_latency_seconds", 1.2);

    const output = formatMetrics();
    assert.ok(
      output.includes("autopilot_triage_latency_seconds_sum"),
      "formatMetrics should include the latency sum line",
    );
    assert.ok(
      output.includes("autopilot_triage_latency_seconds_count"),
      "formatMetrics should include the latency count line",
    );
  });

  it("formatMetrics returns string containing metric names", () => {
    const output = formatMetrics();
    assert.equal(typeof output, "string");
    assert.ok(output.length > 0, "formatMetrics output should not be empty");
    // Should contain at least some core metric names
    assert.ok(output.includes("autopilot_cases_created_total"));
    assert.ok(output.includes("autopilot_alerts_ingested_total"));
  });

  it("formatMetrics includes autopilot_ prefix on all metrics", () => {
    const output = formatMetrics();
    const lines = output.split("\n").filter((l) => l && !l.startsWith("#"));
    for (const line of lines) {
      assert.ok(
        line.startsWith("autopilot_"),
        `Expected line to start with "autopilot_", got: "${line}"`,
      );
    }
  });
});
