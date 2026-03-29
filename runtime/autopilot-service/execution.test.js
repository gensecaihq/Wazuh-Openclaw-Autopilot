#!/usr/bin/env node
/**
 * Wazuh OpenClaw Autopilot - Plan Execution Tests
 *
 * Tests the full executePlan path with responder ENABLED
 * and a mock MCP server. Each test file runs in its own
 * process so env vars set here won't affect other tests.
 */

const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs").promises;
const path = require("path");
const os = require("os");

// Configure env BEFORE requiring the module (runs in separate child process)
const TEST_MCP_PORT = 19876 + Math.floor(Math.random() * 100);
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `autopilot-exec-test-${Date.now()}`);
process.env.MCP_URL = `http://127.0.0.1:${TEST_MCP_PORT}`;
process.env.AUTOPILOT_MCP_AUTH = "test-mcp-auth-token-12345678";
process.env.AUTOPILOT_RESPONDER_ENABLED = "true";
process.env.MCP_MAX_RETRIES = "1";
process.env.MCP_RETRY_BASE_MS = "50";
process.env.MCP_TIMEOUT_MS = "5000";
process.env.MAX_CONCURRENT_EXECUTIONS = "2";
process.env.MCP_AUTH_MODE = "legacy-rest";

const {
  createCase,
  updateCase,
  getCase,
  createResponsePlan,
  approvePlan,
  rejectPlan,
  executePlan,
  getPlan,
  getResponderStatus,
  PLAN_STATES,
} = require("./index.js");

// =============================================================================
// Mock MCP Server
// =============================================================================

let mockMcpServer;
let mcpRequestLog = [];
let mcpResponseHandler = null;

function startMockMcp() {
  return new Promise((resolve) => {
    mockMcpServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        const entry = {
          method: req.method,
          url: req.url,
          headers: req.headers,
          body: body ? JSON.parse(body) : null,
        };
        mcpRequestLog.push(entry);

        if (mcpResponseHandler) {
          mcpResponseHandler(req, res, entry);
        } else {
          // Default: success response
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, result: "action completed" }));
        }
      });
    });
    mockMcpServer.listen(TEST_MCP_PORT, "127.0.0.1", resolve);
  });
}

function stopMockMcp() {
  return new Promise((resolve) => {
    if (mockMcpServer) {
      mockMcpServer.close(resolve);
    } else {
      resolve();
    }
  });
}

// =============================================================================
// Helper: create an approved plan ready for execution
// =============================================================================

async function createApprovedPlan(actions) {
  // Create a case first
  await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
  await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

  const caseId = `CASE-exec-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const caseData = await createCase(caseId, {
    title: "Test execution case",
    severity: "high",
    entities: [{ type: "ip", value: "10.0.0.99" }],
  });

  const plan = createResponsePlan({
    case_id: caseData.case_id,
    risk_level: "medium",
    actions: actions || [
      { type: "block_ip", target: "10.0.0.99", params: { ip: "10.0.0.99", direction: "inbound" } },
    ],
  });

  // Tier 1: Approve
  const approved = approvePlan(plan.plan_id, "approver-001", "Test approval");
  assert.equal(approved.state, PLAN_STATES.APPROVED);

  return approved;
}

// =============================================================================
// Tests
// =============================================================================

describe("Plan Execution (Responder Enabled)", () => {
  before(async () => {
    await startMockMcp();
  });

  after(async () => {
    await stopMockMcp();
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true }).catch(() => {});
  });

  beforeEach(() => {
    mcpRequestLog = [];
    mcpResponseHandler = null;
  });

  afterEach(async () => {
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true }).catch(() => {});
  });

  it("responder status shows enabled", () => {
    const status = getResponderStatus();
    assert.equal(status.enabled, true);
    assert.equal(status.human_approval_required, true);
    assert.equal(status.autonomous_execution, false);
  });

  it("executes a single-action plan successfully", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.99", params: { ip: "10.0.0.99" } },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    assert.equal(result.state, PLAN_STATES.COMPLETED);
    assert.equal(result.execution_result.success, true);
    assert.equal(result.execution_result.actions_total, 1);
    assert.equal(result.execution_result.actions_success, 1);
    assert.equal(result.execution_result.actions_failed, 0);
    assert.equal(result.executor_id, "executor-001");
    assert.ok(result.executed_at);

    // Verify MCP was called
    assert.equal(mcpRequestLog.length, 1);
    assert.ok(mcpRequestLog[0].url.includes("block_ip"));
  });

  it("executes a multi-action plan with all actions succeeding", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: { ip: "10.0.0.1" } },
      { type: "isolate_host", target: "srv-web-01", params: { host: "srv-web-01" } },
      { type: "disable_user", target: "jdoe", params: { username: "jdoe" } },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    assert.equal(result.state, PLAN_STATES.COMPLETED);
    assert.equal(result.execution_result.success, true);
    assert.equal(result.execution_result.actions_total, 3);
    assert.equal(result.execution_result.actions_success, 3);
    assert.equal(mcpRequestLog.length, 3);
  });

  it("handles partial failure (some MCP calls fail)", async () => {
    // Track calls per tool name to consistently fail one tool
    mcpResponseHandler = (req, res) => {
      if (req.url.includes("isolate_host")) {
        // Always fail isolate_host (both initial + retry)
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      }
    };

    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: { ip: "10.0.0.1" } },
      { type: "isolate_host", target: "srv-fail", params: { host: "srv-fail" } },
      { type: "disable_user", target: "jdoe", params: { username: "jdoe" } },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    assert.equal(result.state, PLAN_STATES.FAILED);
    assert.equal(result.execution_result.success, false);
    assert.equal(result.execution_result.actions_total, 3);
    assert.ok(result.execution_result.actions_failed >= 1);
    // First and third succeed, second fails
    assert.equal(result.execution_result.actions_success, 2);
  });

  it("handles MCP server returning non-ok response", async () => {
    mcpResponseHandler = (_req, res) => {
      // Return 400 bad request (not retried since < 500)
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Bad request" }));
    };

    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: { ip: "10.0.0.1" } },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    // callMcpTool returns {success: false} for non-ok responses
    assert.equal(result.state, PLAN_STATES.FAILED);
    assert.equal(result.execution_result.success, false);
    assert.equal(result.execution_result.results[0].status, "failed");
  });

  it("prevents executing a plan that is not approved", async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    const caseId = `CASE-nonapproved-${Date.now()}`;
    const caseData = await createCase(caseId, {
      title: "Test non-approved",
      severity: "low",
      entities: [],
    });

    const plan = createResponsePlan({
      case_id: caseData.case_id,
      risk_level: "low",
      actions: [{ type: "block_ip", target: "10.0.0.1", params: {} }],
    });

    // Try to execute without approving (still in PROPOSED state)
    await assert.rejects(
      () => executePlan(plan.plan_id, "executor-001"),
      (err) => {
        assert.ok(err.message.includes("Tier 1 required"));
        return true;
      },
    );
  });

  it("prevents double execution of the same plan", async () => {
    // Use a slow MCP response to create a window
    mcpResponseHandler = (_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      }, 200);
    };

    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: {} },
    ]);

    // Start execution (don't await)
    const exec1 = executePlan(plan.plan_id, "executor-001");

    // Try second execution immediately — should fail because plan state is now EXECUTING
    await assert.rejects(
      () => executePlan(plan.plan_id, "executor-002"),
      (err) => {
        assert.ok(
          err.message.includes("already being executed") ||
          err.message.includes("Cannot execute plan in state"),
        );
        return true;
      },
    );

    // Wait for first to complete
    await exec1;
  });

  it("rejects block_ip with domain name instead of IP address", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "europaest.bitcompany.it", params: {} },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    assert.equal(result.state, PLAN_STATES.FAILED);
    assert.equal(result.execution_result.success, false);
    assert.equal(result.execution_result.results[0].status, "error");
    assert.ok(result.execution_result.results[0].error.includes("not a valid IP address"));
  });

  it("allows block_ip with valid IPv4 address", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "91.224.92.118", params: {} },
    ]);

    const result = await executePlan(plan.plan_id, "executor-001");

    assert.equal(result.state, PLAN_STATES.COMPLETED);
    assert.equal(result.execution_result.success, true);
  });

  it("prevents rejecting a plan that is currently executing", async () => {
    mcpResponseHandler = (_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      }, 200);
    };

    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: {} },
    ]);

    // Start execution (don't await)
    const exec = executePlan(plan.plan_id, "executor-001");

    // Try to reject while executing
    assert.throws(
      () => rejectPlan(plan.plan_id, "rejector-001", "too late"),
      (err) => {
        assert.ok(err.message.includes("currently executing"));
        return true;
      },
    );

    await exec;
  });

  it("enforces concurrent execution limit", async () => {
    // MAX_CONCURRENT_EXECUTIONS is set to 2
    mcpResponseHandler = (_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      }, 300);
    };

    const plan1 = await createApprovedPlan([{ type: "block_ip", target: "10.0.0.1", params: {} }]);
    const plan2 = await createApprovedPlan([{ type: "block_ip", target: "10.0.0.2", params: {} }]);
    const plan3 = await createApprovedPlan([{ type: "block_ip", target: "10.0.0.3", params: {} }]);

    // Start two executions (at limit)
    const exec1 = executePlan(plan1.plan_id, "executor-001");
    const exec2 = executePlan(plan2.plan_id, "executor-002");

    // Third should be rejected
    await assert.rejects(
      () => executePlan(plan3.plan_id, "executor-003"),
      (err) => {
        assert.ok(err.message.includes("Concurrent execution limit"));
        return true;
      },
    );

    // Wait for running plans to complete
    await Promise.all([exec1, exec2]);

    // Now plan3 should be executable (still in approved state)
    const result3 = await executePlan(plan3.plan_id, "executor-003");
    assert.equal(result3.state, PLAN_STATES.COMPLETED);
  });

  it("records execution results in the plan object", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.99", params: { ip: "10.0.0.99" } },
    ]);

    await executePlan(plan.plan_id, "executor-001");

    // Fetch the plan again to verify results are persisted
    const fetched = getPlan(plan.plan_id);
    assert.ok(fetched.execution_result);
    assert.equal(fetched.execution_result.actions_total, 1);
    assert.ok(Array.isArray(fetched.execution_result.results));
    assert.equal(fetched.execution_result.results[0].action_type, "block_ip");
    assert.equal(fetched.execution_result.results[0].target, "10.0.0.99");
    assert.ok(fetched.execution_result.results[0].timestamp);
  });

  it("passes correct parameters to MCP server", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.42", params: { ip: "10.0.0.42", direction: "both" } },
    ]);

    await executePlan(plan.plan_id, "executor-001");

    assert.equal(mcpRequestLog.length, 1);
    const mcpCall = mcpRequestLog[0];
    assert.equal(mcpCall.method, "POST");
    assert.ok(mcpCall.url.includes("block_ip"));
    // buildMcpParams injects action.target as the target param name (fallback: "target")
    // block_ip now auto-injects agent_id: "001" (Wazuh manager) when not specified
    assert.deepStrictEqual(mcpCall.body, { ip: "10.0.0.42", direction: "both", target: "10.0.0.42", agent_id: "001" });
    assert.ok(mcpCall.headers["authorization"]);
    assert.ok(mcpCall.headers["x-correlation-id"]);
  });

  it("transitions case status to executed after successful plan execution", async () => {
    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.99", params: { ip: "10.0.0.99" } },
    ]);

    // Walk case through valid status transitions to reach "approved"
    // open → triaged → correlated → investigated → planned → approved
    await updateCase(plan.case_id, { status: "triaged" });
    await updateCase(plan.case_id, { status: "correlated" });
    await updateCase(plan.case_id, { status: "investigated" });
    await updateCase(plan.case_id, { status: "planned" });
    await updateCase(plan.case_id, { status: "approved" });

    const result = await executePlan(plan.plan_id, "executor-001");
    assert.equal(result.state, PLAN_STATES.COMPLETED);
    assert.equal(result.execution_result.success, true);

    // Verify case status is now "executed"
    const caseAfter = await getCase(plan.case_id);
    assert.equal(caseAfter.status, "executed");
  });

  it("transitions case status to executed even with partial action failure", async () => {
    mcpResponseHandler = (_req, res, entry) => {
      // Always fail requests targeting 10.0.0.1 (in URL or body), succeed the rest
      const bodyStr = JSON.stringify(entry.body || {});
      if (entry.url.includes("10.0.0.1") || bodyStr.includes("10.0.0.1")) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "simulated failure" }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      }
    };

    const plan = await createApprovedPlan([
      { type: "block_ip", target: "10.0.0.1", params: { ip: "10.0.0.1" } },
      { type: "block_ip", target: "10.0.0.2", params: { ip: "10.0.0.2" } },
      { type: "block_ip", target: "10.0.0.3", params: { ip: "10.0.0.3" } },
    ]);

    // Walk case through valid status transitions to reach "approved"
    await updateCase(plan.case_id, { status: "triaged" });
    await updateCase(plan.case_id, { status: "correlated" });
    await updateCase(plan.case_id, { status: "investigated" });
    await updateCase(plan.case_id, { status: "planned" });
    await updateCase(plan.case_id, { status: "approved" });

    const result = await executePlan(plan.plan_id, "executor-001");
    assert.equal(result.state, PLAN_STATES.FAILED);
    assert.equal(result.execution_result.success, false);
    assert.ok(result.execution_result.actions_failed >= 1);

    // Verify case status is still "executed" even with partial failure
    const caseAfter = await getCase(plan.case_id);
    assert.equal(caseAfter.status, "executed");
  });

  it("rejects kill_process without process_id at plan creation", async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    const caseId = `CASE-killproc-${Date.now()}`;
    await createCase(caseId, { title: "Test", severity: "high", entities: [] });

    assert.throws(
      () => createResponsePlan({
        case_id: caseId,
        risk_level: "high",
        actions: [{ type: "kill_process", target: "agent-001" }],
      }),
      (err) => {
        assert.ok(err.message.includes("kill_process"));
        assert.ok(err.message.includes("process_id"));
        return true;
      },
    );
  });

  it("rejects disable_user without username at plan creation", async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    const caseId = `CASE-disuser-${Date.now()}`;
    await createCase(caseId, { title: "Test", severity: "high", entities: [] });

    assert.throws(
      () => createResponsePlan({
        case_id: caseId,
        risk_level: "high",
        actions: [{ type: "disable_user", target: "agent-002" }],
      }),
      (err) => {
        assert.ok(err.message.includes("disable_user"));
        assert.ok(err.message.includes("username"));
        return true;
      },
    );
  });

  it("rejects quarantine_file without file_path at plan creation", async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    const caseId = `CASE-quarfile-${Date.now()}`;
    await createCase(caseId, { title: "Test", severity: "high", entities: [] });

    assert.throws(
      () => createResponsePlan({
        case_id: caseId,
        risk_level: "high",
        actions: [{ type: "quarantine_file", target: "agent-003" }],
      }),
      (err) => {
        assert.ok(err.message.includes("quarantine_file"));
        assert.ok(err.message.includes("file_path"));
        return true;
      },
    );
  });

  it("accepts kill_process with valid process_id", async () => {
    const plan = await createApprovedPlan([
      { type: "kill_process", target: "agent-001", params: { process_id: 9876 } },
    ]);
    assert.ok(plan.plan_id);
    assert.equal(plan.actions[0].type, "kill_process");
    assert.equal(plan.actions[0].params.process_id, 9876);
  });

  it("rejects plan creation with invalid action fields", async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    const caseId = `CASE-invalid-${Date.now()}`;
    await createCase(caseId, { title: "Test", severity: "low", entities: [] });

    // createResponsePlan should reject actions with missing type/target
    assert.throws(
      () => createResponsePlan({
        case_id: caseId,
        risk_level: "low",
        actions: [
          { type: "block_ip", target: "10.0.0.1", params: {} },
          { type: "", target: "" }, // Invalid
        ],
      }),
      (err) => {
        assert.ok(err.message.includes("Invalid actions"));
        return true;
      },
    );
  });
});
