/**
 * YAML parsing and toolmap resolution tests.
 *
 * Uses Node.js built-in test runner -- no external dependencies.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");

// Set env vars BEFORE requiring index.js
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `yaml-test-${Date.now()}`);
process.env.AUTOPILOT_CONFIG_DIR = path.join(os.tmpdir(), `yaml-config-${Date.now()}`);

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");

const {
  parseSimpleYaml,
  loadToolmap,
  resolveMcpTool,
  isToolEnabled,
} = require("./index.js");

const dataDir = process.env.AUTOPILOT_DATA_DIR;
const configDir = process.env.AUTOPILOT_CONFIG_DIR;

describe("parseSimpleYaml", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(configDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("parses simple key-value pair", () => {
    const result = parseSimpleYaml("name: autopilot");
    assert.equal(result.name, "autopilot");
  });

  it("parses multiple key-value pairs", () => {
    const yaml = [
      "host: localhost",
      "port: 9090",
      "service: wazuh-autopilot",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.equal(result.host, "localhost");
    assert.equal(result.port, 9090);
    assert.equal(result.service, "wazuh-autopilot");
  });

  it("parses boolean values (true/false)", () => {
    const yaml = [
      "enabled: true",
      "debug: false",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.strictEqual(result.enabled, true);
    assert.strictEqual(result.debug, false);
  });

  it("parses numeric values (integer and float)", () => {
    const yaml = [
      "max_retries: 5",
      "timeout: 30",
      "threshold: 0.85",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.strictEqual(result.max_retries, 5);
    assert.strictEqual(result.timeout, 30);
    assert.strictEqual(result.threshold, 0.85);
  });

  it("parses null values", () => {
    const yaml = "optional_field: null";
    const result = parseSimpleYaml(yaml);
    assert.strictEqual(result.optional_field, null);
  });

  it("parses nested objects", () => {
    const yaml = [
      "database:",
      "  host: db.local",
      "  port: 5432",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.ok(result.database, "Should have nested database object");
    assert.equal(result.database.host, "db.local");
    assert.equal(result.database.port, 5432);
  });

  it("parses list items", () => {
    // The simple YAML parser expects list items at the same indent level as
    // the parent key (no extra indentation), matching its stack-based approach.
    const yaml = [
      "tags:",
      "- ssh",
      "- brute-force",
      "- critical",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.ok(Array.isArray(result.tags), "tags should be an array");
    assert.equal(result.tags.length, 3);
    assert.equal(result.tags[0], "ssh");
    assert.equal(result.tags[1], "brute-force");
    assert.equal(result.tags[2], "critical");
  });

  it("handles comments by skipping them", () => {
    const yaml = [
      "# This is a comment",
      "key: value",
      "  # Indented comment",
      "other: data",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.equal(result.key, "value");
    assert.equal(result.other, "data");
    assert.equal(Object.keys(result).length, 2);
  });

  it("handles empty content and returns empty object", () => {
    const result1 = parseSimpleYaml("");
    assert.strictEqual(Object.keys(result1).length, 0);
    const result2 = parseSimpleYaml("   \n\n  ");
    assert.strictEqual(Object.keys(result2).length, 0);
  });

  it("handles quoted string values by stripping quotes", () => {
    const yaml = [
      'label: "hello world"',
      "description: 'single quoted'",
    ].join("\n");
    const result = parseSimpleYaml(yaml);
    assert.equal(result.label, "hello world");
    assert.equal(result.description, "single quoted");
  });
});

describe("loadToolmap, resolveMcpTool, isToolEnabled", () => {
  const policiesDir = path.join(configDir, "policies");

  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(policiesDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("loadToolmap loads defaults when toolmap.yaml is missing", async () => {
    const map = await loadToolmap();
    assert.ok(map, "loadToolmap should return an object");
    assert.ok(map.read_operations, "Should have read_operations");
    assert.ok(map.action_operations, "Should have action_operations");
  });

  it("resolveMcpTool returns the MCP tool name for a known logical name", async () => {
    // loadToolmap was called above, so the default config is loaded
    await loadToolmap();
    const resolved = resolveMcpTool("get_alert");
    assert.equal(resolved, "wazuh_get_alert");
  });

  it("resolveMcpTool returns the logical name unchanged for unknown tools", async () => {
    await loadToolmap();
    const resolved = resolveMcpTool("unknown_tool_xyz");
    assert.equal(resolved, "unknown_tool_xyz");
  });

  it("isToolEnabled returns true for enabled read operations", async () => {
    await loadToolmap();
    assert.equal(isToolEnabled("get_alert"), true);
    assert.equal(isToolEnabled("search_alerts"), true);
  });

  it("isToolEnabled returns false for disabled action operations", async () => {
    await loadToolmap();
    assert.equal(isToolEnabled("block_ip"), false);
    assert.equal(isToolEnabled("isolate_host"), false);
  });

  it("isToolEnabled returns true for unknown tools (default)", async () => {
    await loadToolmap();
    assert.equal(isToolEnabled("nonexistent_tool"), true);
  });
});
