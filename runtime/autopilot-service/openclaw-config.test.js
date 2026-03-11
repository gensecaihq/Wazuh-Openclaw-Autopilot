/**
 * Validation tests for OpenClaw configuration files.
 *
 * Ensures that all openclaw.json configs use the correct tool registration
 * semantics (`alsoAllow` not `allow`) so that tools like web_fetch are
 * actually registered in the API request and agents get stopReason "tool_use"
 * instead of "stop".
 *
 * See: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues/16
 *
 * Run:  node --test openclaw-config.test.js
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Strip JSON5 comments (// and /* ... * /) to produce valid JSON.
 * Handles comments inside strings correctly by skipping quoted regions.
 */
function stripJson5Comments(text) {
  let result = "";
  let i = 0;
  while (i < text.length) {
    // Skip strings
    if (text[i] === '"') {
      result += '"';
      i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === "\\") {
          result += text[i] + text[i + 1];
          i += 2;
        } else {
          result += text[i];
          i++;
        }
      }
      if (i < text.length) {
        result += '"';
        i++;
      }
      continue;
    }
    // Line comment
    if (text[i] === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    // Block comment
    if (text[i] === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    result += text[i];
    i++;
  }
  // Strip trailing commas before } or ]
  return result.replace(/,\s*([}\]])/g, "$1");
}

/**
 * Load and parse a JSON5 config file, returning the parsed object.
 */
function loadJson5(filePath) {
  const raw = fs.readFileSync(filePath, "utf-8");
  const cleaned = stripJson5Comments(raw);
  return JSON.parse(cleaned);
}

const ROOT = path.resolve(__dirname, "..", "..");
const CONFIGS = [
  { name: "openclaw.json", path: path.join(ROOT, "openclaw", "openclaw.json") },
  { name: "openclaw-airgapped.json", path: path.join(ROOT, "openclaw", "openclaw-airgapped.json") },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OpenClaw config tool registration (issue #16)", () => {
  for (const cfg of CONFIGS) {
    describe(cfg.name, () => {
      let config;

      it("parses without error", () => {
        config = loadJson5(cfg.path);
        assert.ok(config, "Config should parse successfully");
      });

      it("global tools block uses alsoAllow, not allow", () => {
        config = config || loadJson5(cfg.path);
        const tools = config.tools;
        assert.ok(tools, "Global tools block should exist");
        assert.ok(tools.alsoAllow, "Global tools should use 'alsoAllow'");
        assert.equal(tools.allow, undefined, "Global tools should NOT have 'allow' key — use 'alsoAllow' instead");
      });

      it("global tools.alsoAllow includes web_fetch", () => {
        config = config || loadJson5(cfg.path);
        assert.ok(
          config.tools.alsoAllow.includes("web_fetch"),
          "Global alsoAllow must include web_fetch",
        );
      });

      it("every agent tools block uses alsoAllow, not allow", () => {
        config = config || loadJson5(cfg.path);
        const agents = config.agents?.list || [];
        assert.ok(agents.length > 0, "Should have at least one agent");

        for (const agent of agents) {
          if (!agent.tools) continue;
          assert.ok(
            agent.tools.alsoAllow,
            `Agent '${agent.id}' tools should use 'alsoAllow'`,
          );
          assert.equal(
            agent.tools.allow,
            undefined,
            `Agent '${agent.id}' tools should NOT have 'allow' — use 'alsoAllow' instead`,
          );
        }
      });

      it("every agent tools.alsoAllow includes web_fetch", () => {
        config = config || loadJson5(cfg.path);
        const agents = config.agents?.list || [];

        for (const agent of agents) {
          if (!agent.tools?.alsoAllow) continue;
          assert.ok(
            agent.tools.alsoAllow.includes("web_fetch"),
            `Agent '${agent.id}' alsoAllow must include web_fetch`,
          );
        }
      });

      it("every agent tools.alsoAllow includes session tools for inter-agent comms", () => {
        config = config || loadJson5(cfg.path);
        const agents = config.agents?.list || [];
        const sessionTools = ["sessions_list", "sessions_history", "sessions_send"];

        for (const agent of agents) {
          if (!agent.tools?.alsoAllow) continue;
          for (const tool of sessionTools) {
            assert.ok(
              agent.tools.alsoAllow.includes(tool),
              `Agent '${agent.id}' alsoAllow must include '${tool}'`,
            );
          }
        }
      });

      it("allowUnsafeExternalContent is set on all hook mappings", () => {
        config = config || loadJson5(cfg.path);
        const mappings = config.hooks?.mappings || [];
        if (mappings.length === 0) return; // air-gapped may not have hooks

        for (const mapping of mappings) {
          assert.equal(
            mapping.allowUnsafeExternalContent,
            true,
            `Hook mapping '${mapping.name}' must have allowUnsafeExternalContent: true`,
          );
        }
      });

      it("tools.web.fetch.enabled is true", () => {
        config = config || loadJson5(cfg.path);
        assert.equal(
          config.tools?.web?.fetch?.enabled,
          true,
          "tools.web.fetch.enabled must be true for agents to use web_fetch",
        );
      });

      it("tools.web.fetch has no unrecognized keys (OpenClaw strict schema)", () => {
        config = config || loadJson5(cfg.path);
        const fetch = config.tools?.web?.fetch || {};
        const validKeys = ["enabled", "maxChars", "maxCharsCap", "timeoutSeconds", "cacheTtlMinutes", "maxRedirects", "userAgent"];
        for (const key of Object.keys(fetch)) {
          assert.ok(
            validKeys.includes(key),
            `tools.web.fetch.${key} is not a valid OpenClaw config key — will crash gateway startup`,
          );
        }
      });
    });
  }
});

describe("install.sh config template uses alsoAllow", () => {
  const installSh = path.join(ROOT, "install", "install.sh");

  it("install.sh exists", () => {
    assert.ok(fs.existsSync(installSh), "install/install.sh should exist");
  });

  it("contains no tools.allow (only alsoAllow) in JSON config blocks", () => {
    const content = fs.readFileSync(installSh, "utf-8");
    // Match "allow": [...] but NOT "alsoAllow" and NOT "allowUnsafeExternalContent"
    const badPattern = /"allow"\s*:\s*\[/g;
    const matches = content.match(badPattern);
    assert.equal(
      matches,
      null,
      `install.sh should not contain "allow": [...] in tool blocks — use "alsoAllow" instead. Found ${matches ? matches.length : 0} occurrences`,
    );
  });

  it("contains alsoAllow entries for tool registration", () => {
    const content = fs.readFileSync(installSh, "utf-8");
    const alsoAllowPattern = /"alsoAllow"\s*:\s*\[/g;
    const matches = content.match(alsoAllowPattern);
    assert.ok(
      matches && matches.length >= 8,
      `install.sh should have at least 8 alsoAllow entries (7 agents + 1 global), found ${matches ? matches.length : 0}`,
    );
  });

  it("does not contain unrecognized OpenClaw config keys", () => {
    const content = fs.readFileSync(installSh, "utf-8");
    assert.ok(
      !content.includes('"allowPrivateNetwork"'),
      "install.sh must not contain allowPrivateNetwork — rejected by OpenClaw strict schema",
    );
  });
});

describe("Agent AGENTS.md files reference web_fetch correctly", () => {
  const agentsDir = path.join(ROOT, "openclaw", "agents");
  const agentNames = ["triage", "correlation", "investigation", "response-planner", "policy-guard", "responder"];

  for (const name of agentNames) {
    it(`${name}/AGENTS.md contains web_fetch invocation syntax`, () => {
      const agentMd = path.join(agentsDir, name, "AGENTS.md");
      if (!fs.existsSync(agentMd)) return; // skip if not present
      const content = fs.readFileSync(agentMd, "utf-8");
      assert.ok(
        content.includes("web_fetch(url="),
        `${name}/AGENTS.md should contain web_fetch(url=...) invocation syntax`,
      );
    });
  }
});

describe("E2E pipeline with agent-action GET endpoints", () => {
  // This test validates the full pipeline flow using the same GET endpoints
  // that agents use via web_fetch — proving the runtime correctly handles
  // the tool calls that agents will make once alsoAllow is configured.

  const os = require("os");
  const http = require("http");

  const TEST_DATA_DIR = path.join(
    os.tmpdir(),
    `autopilot-e2e-config-test-${Date.now()}-${process.pid}`,
  );

  process.env.AUTOPILOT_MODE = "bootstrap";
  process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
  process.env.AUTOPILOT_MCP_AUTH = "test-mcp-secret-token";
  process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-token";
  process.env.AUTOPILOT_RESPONDER_ENABLED = "false";
  process.env.RATE_LIMIT_MAX_REQUESTS = "500";
  process.env.RATE_LIMIT_WINDOW_MS = "60000";
  process.env.LOG_LEVEL = "error";

  const { createServer } = require("./index");

  function req(server, method, urlPath, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const addr = server.address();
      const opts = {
        hostname: "127.0.0.1",
        port: addr.port,
        path: urlPath,
        method,
        headers: { ...headers },
      };
      if (body) {
        const data = JSON.stringify(body);
        opts.headers["Content-Type"] = "application/json";
        opts.headers["Content-Length"] = Buffer.byteLength(data);
      }
      const r = http.request(opts, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          let parsed;
          try { parsed = JSON.parse(raw); } catch { parsed = raw; }
          resolve({ status: res.statusCode, body: parsed, raw });
        });
      });
      r.on("error", reject);
      if (body) r.write(JSON.stringify(body));
      r.end();
    });
  }

  let server;
  let caseId;

  it("setup: start server and create alert", async () => {
    fs.mkdirSync(path.join(TEST_DATA_DIR, "cases"), { recursive: true });
    fs.mkdirSync(path.join(TEST_DATA_DIR, "plans"), { recursive: true });
    fs.mkdirSync(path.join(TEST_DATA_DIR, "policies"), { recursive: true });
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

    const res = await req(server, "POST", "/api/alerts", {
      alert_id: "e2e-config-001",
      rule: { id: "5712", level: 10, description: "SSH brute force" },
      agent: { id: "001", name: "test-srv", ip: "10.0.1.50" },
      data: { srcip: "198.51.100.10" },
    }, { Authorization: "Bearer test-mcp-secret-token" });

    assert.equal(res.status, 201, `Expected 201, got ${res.status}: ${res.raw}`);
    caseId = res.body.case_id;
    assert.ok(caseId, "Case ID should be returned");
  });

  it("agent-action/update-case advances to triaged via GET (simulates web_fetch)", async () => {
    // This is exactly what the triage agent does via web_fetch
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=triaged`,
    );
    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.raw}`);
    assert.equal(res.body.status, "triaged");
  });

  it("case status is now triaged", async () => {
    const res = await req(server, "GET", `/api/cases/${caseId}`, null, {
      Authorization: "Bearer test-mcp-secret-token",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "triaged");
  });

  it("agent-action/update-case advances to correlated via GET (simulates web_fetch)", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=correlated`,
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "correlated");
  });

  it("agent-action/update-case advances to investigated via GET (simulates web_fetch)", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=investigated`,
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "investigated");
  });

  it("agent-action/create-plan creates a plan via GET (simulates web_fetch)", async () => {
    const actions = encodeURIComponent(JSON.stringify([
      { type: "block_ip", target: "198.51.100.10", params: { ip: "198.51.100.10" } },
    ]));
    const res = await req(
      server,
      "GET",
      `/api/agent-action/create-plan?case_id=${caseId}&risk_level=medium&title=Block+attacker+IP&description=Block+SSH+brute+force+source&actions=${actions}`,
    );
    assert.equal(res.status, 201, `Expected 201, got ${res.status}: ${res.raw}`);
    assert.ok(res.body.plan_id, "Plan ID should be returned");
    assert.equal(res.body.state, "proposed");
  });

  it("cleanup: stop server", async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  });
});

describe("Query parameter auth for agent-action endpoints (Issue #17/#18)", () => {
  const os = require("os");
  const http = require("http");

  const TEST_DATA_DIR = path.join(
    os.tmpdir(),
    `autopilot-query-auth-test-${Date.now()}-${process.pid}`,
  );

  // Use production mode to disable localhost bypass — forces token auth
  process.env.AUTOPILOT_MODE = "production";
  process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
  process.env.AUTOPILOT_MCP_AUTH = "test-query-auth-token-value";
  process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-read-token";
  process.env.AUTOPILOT_RESPONDER_ENABLED = "false";
  process.env.RATE_LIMIT_MAX_REQUESTS = "500";
  process.env.RATE_LIMIT_WINDOW_MS = "60000";
  process.env.LOG_LEVEL = "error";
  // Tailnet check bypass for production mode in tests
  process.env.MCP_URL = "https://mcp.tailnet.ts.net:3000";

  // Re-require to pick up new env vars
  delete require.cache[require.resolve("./index")];
  const { createServer: createServerAuth } = require("./index");

  function req(server, method, urlPath, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const addr = server.address();
      const opts = {
        hostname: "127.0.0.1",
        port: addr.port,
        path: urlPath,
        method,
        headers: { ...headers },
      };
      if (body) {
        const data = JSON.stringify(body);
        opts.headers["Content-Type"] = "application/json";
        opts.headers["Content-Length"] = Buffer.byteLength(data);
      }
      const r = http.request(opts, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          let parsed;
          try { parsed = JSON.parse(raw); } catch { parsed = raw; }
          resolve({ status: res.statusCode, body: parsed, raw });
        });
      });
      r.on("error", reject);
      if (body) r.write(JSON.stringify(body));
      r.end();
    });
  }

  let server;
  let caseId;

  it("setup: start server in production mode and create alert", async () => {
    fs.mkdirSync(path.join(TEST_DATA_DIR, "cases"), { recursive: true });
    fs.mkdirSync(path.join(TEST_DATA_DIR, "plans"), { recursive: true });
    fs.mkdirSync(path.join(TEST_DATA_DIR, "policies"), { recursive: true });
    server = createServerAuth();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

    const res = await req(server, "POST", "/api/alerts", {
      alert_id: "query-auth-001",
      rule: { id: "5712", level: 10, description: "SSH brute force" },
      agent: { id: "001", name: "test-srv", ip: "10.0.1.50" },
      data: { srcip: "198.51.100.20" },
    }, { Authorization: "Bearer test-query-auth-token-value" });

    assert.equal(res.status, 201, `Expected 201, got ${res.status}: ${res.raw}`);
    caseId = res.body.case_id;
    assert.ok(caseId, "Case ID should be returned");
  });

  it("GET without auth returns 401 in production mode", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=triaged`,
    );
    assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${res.raw}`);
  });

  it("GET with ?token= query param authenticates successfully", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=triaged&token=test-query-auth-token-value`,
    );
    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.raw}`);
    assert.equal(res.body.status, "triaged");
  });

  it("GET with invalid ?token= returns 401", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=correlated&token=wrong-token-value-here`,
    );
    assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${res.raw}`);
  });

  it("GET /api/cases with ?token= works for read endpoints", async () => {
    const res = await req(
      server,
      "GET",
      `/api/cases/${caseId}?token=test-query-auth-token-value`,
    );
    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.raw}`);
    assert.equal(res.body.status, "triaged");
  });

  it("Bearer header still works alongside query token support", async () => {
    const res = await req(
      server,
      "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=correlated`,
      null,
      { Authorization: "Bearer test-query-auth-token-value" },
    );
    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.raw}`);
    assert.equal(res.body.status, "correlated");
  });

  it("cleanup: stop server", async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
    // Restore bootstrap mode for other tests
    process.env.AUTOPILOT_MODE = "bootstrap";
  });
});
