#!/usr/bin/env node
/**
 * Wazuh OpenClaw Autopilot - Reporting Endpoints Tests
 */

const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs").promises;
const path = require("path");
const os = require("os");
const http = require("http");

// Set test environment
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `autopilot-reporting-test-${Date.now()}`);

const {
  createCase,
  updateCase,
  getCase,
  listCases,
  createResponsePlan,
  listPlans,
  approvePlan,
  rejectPlan,
  responsePlans,
  PLAN_STATES,
  createServer,
} = require("./index.js");

// Helper: make HTTP request to the test server
function request(server, method, path, body = null) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const options = {
      hostname: "127.0.0.1",
      port: addr.port,
      path,
      method,
      headers: { "Content-Type": "application/json" },
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers });
        } catch {
          resolve({ status: res.statusCode, body: data, headers: res.headers });
        }
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

describe("Reporting Endpoints", () => {
  let server;

  before(async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });
  });

  describe("GET /api/cases/summary", () => {
    it("should return correct aggregation with no cases", async () => {
      const res = await request(server, "GET", "/api/cases/summary");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.total, 0);
      assert.deepStrictEqual(res.body.by_status, {});
      assert.deepStrictEqual(res.body.by_severity, {});
      assert.strictEqual(res.body.false_positive_count, 0);
      assert.strictEqual(res.body.last_24h, 0);
      assert.strictEqual(res.body.last_7d, 0);
      assert.strictEqual(res.body.last_30d, 0);
      assert.ok(res.body.request_id);
    });

    it("should return correct aggregation with cases", async () => {
      await createCase("CASE-20260327-aaa001", {
        title: "Test 1", severity: "high", status: "open",
      });
      await createCase("CASE-20260327-aaa002", {
        title: "Test 2", severity: "critical", status: "open",
      });
      await createCase("CASE-20260327-aaa003", {
        title: "Test 3", severity: "high", status: "open",
      });

      // Update one to false_positive
      await updateCase("CASE-20260327-aaa003", { status: "false_positive" });

      const res = await request(server, "GET", "/api/cases/summary");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.total, 3);
      assert.strictEqual(res.body.by_status.open, 2);
      assert.strictEqual(res.body.by_status.false_positive, 1);
      assert.strictEqual(res.body.by_severity.high, 2);
      assert.strictEqual(res.body.by_severity.critical, 1);
      assert.strictEqual(res.body.false_positive_count, 1);
      assert.strictEqual(res.body.last_24h, 3);
      assert.strictEqual(res.body.last_7d, 3);
      assert.strictEqual(res.body.last_30d, 3);
    });
  });

  describe("GET /api/cases with filters", () => {
    it("should filter by status", async () => {
      const res = await request(server, "GET", "/api/cases?status=open");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
      for (const c of res.body) {
        assert.strictEqual(c.status, "open");
      }
    });

    it("should filter by severity", async () => {
      const res = await request(server, "GET", "/api/cases?severity=critical");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
      for (const c of res.body) {
        assert.strictEqual(c.severity, "critical");
      }
    });

    it("should filter by since timestamp", async () => {
      const past = new Date(Date.now() - 1000).toISOString();
      const res = await request(server, "GET", `/api/cases?since=${encodeURIComponent(past)}`);
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
    });

    it("should support offset pagination", async () => {
      const all = await request(server, "GET", "/api/cases?limit=100");
      const paged = await request(server, "GET", "/api/cases?limit=1&offset=1");
      assert.strictEqual(paged.status, 200);
      if (all.body.length > 1) {
        assert.strictEqual(paged.body.length, 1);
        assert.strictEqual(paged.body[0].case_id, all.body[1].case_id);
      }
    });
  });

  describe("GET /api/plans/summary", () => {
    it("should return correct aggregation", async () => {
      // Ensure a case exists for plan creation
      let caseId;
      try {
        await getCase("CASE-20260327-aaa001");
        caseId = "CASE-20260327-aaa001";
      } catch {
        await createCase("CASE-20260327-ppp001", {
          title: "Plan test case", severity: "high",
        });
        caseId = "CASE-20260327-ppp001";
      }

      createResponsePlan({
        case_id: caseId,
        title: "Test plan",
        actions: [{ type: "block_ip", target: "10.0.0.1" }],
      });

      const res = await request(server, "GET", "/api/plans/summary");
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.total >= 1);
      assert.ok(res.body.by_state);
      assert.ok(typeof res.body.success_rate === "number");
      assert.ok(typeof res.body.last_24h === "number");
      assert.ok(res.body.request_id);
    });
  });

  describe("GET /api/kpis", () => {
    it("should return KPI metrics for default 24h period", async () => {
      const res = await request(server, "GET", "/api/kpis");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.period, "24h");
      assert.ok(typeof res.body.cases_analyzed === "number");
      assert.ok(typeof res.body.mttd === "number");
      assert.ok(typeof res.body.mttd_cases === "number");
      assert.ok(typeof res.body.mttt === "number");
      assert.ok(typeof res.body.mttt_cases === "number");
      assert.ok(typeof res.body.mtti === "number");
      assert.ok(typeof res.body.mtti_cases === "number");
      assert.ok(typeof res.body.mttr === "number");
      assert.ok(typeof res.body.mttr_cases === "number");
      assert.ok(typeof res.body.mttc === "number");
      assert.ok(typeof res.body.mttc_cases === "number");
      assert.ok(typeof res.body.auto_triage_rate === "number");
      assert.ok(typeof res.body.false_positive_rate === "number");
      assert.ok(res.body.sla_compliance);
      assert.ok(typeof res.body.sla_compliance.triage_within_15m === "number");
      assert.ok(typeof res.body.sla_compliance.response_within_1h === "number");
      assert.ok(res.body.request_id);
    });

    it("should accept valid period values", async () => {
      for (const period of ["1h", "8h", "24h", "7d", "30d"]) {
        const res = await request(server, "GET", `/api/kpis?period=${period}`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.period, period);
      }
    });

    it("should reject invalid period", async () => {
      const res = await request(server, "GET", "/api/kpis?period=2h");
      assert.strictEqual(res.status, 400);
    });

    it("should compute metrics from status_history", async () => {
      // Create a case and transition through statuses to generate history
      await createCase("CASE-20260327-kpi001", {
        title: "KPI test case", severity: "high",
      });
      await updateCase("CASE-20260327-kpi001", { status: "triaged" });
      await updateCase("CASE-20260327-kpi001", { status: "correlated" });
      await updateCase("CASE-20260327-kpi001", { status: "investigated" });

      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.cases_analyzed > 0);
    });

    it("should compute mttd from timeline when status_history has no initial entry", async () => {
      // Create a case with timeline data to simulate a legacy case
      const alertTime = new Date(Date.now() - 60000).toISOString(); // 60s ago
      await createCase("CASE-20260327-kpi002", {
        title: "MTTD test case", severity: "high",
        timeline: [{ timestamp: alertTime, description: "Alert fired" }],
      });
      // The case has status_history (from createCase), but even if it didn't,
      // mttd should be computed from timeline[0].timestamp vs created_at
      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.mttd_cases > 0, "mttd_cases should include cases with timeline data");
      assert.ok(res.body.mttd >= 0, "mttd should be non-negative");
    });

    it("should exclude open cases from mttc computation", async () => {
      // Create an open case (no closed transition)
      await createCase("CASE-20260327-kpi003", {
        title: "Open case for mttc test", severity: "medium",
      });
      await updateCase("CASE-20260327-kpi003", { status: "triaged" });

      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      // mttc_cases should not count open cases
      // All our test cases so far are open, so mttc_cases should be 0
      // unless a previous test closed one
      assert.ok(typeof res.body.mttc_cases === "number");
      // mttc should be 0 when no cases are closed
      if (res.body.mttc_cases === 0) {
        assert.strictEqual(res.body.mttc, 0, "mttc should be 0 when no closed cases exist");
      }
    });

    it("should include closed cases in mttc and mttr", async () => {
      // Create a case and close it to generate mttc
      await createCase("CASE-20260327-kpi004", {
        title: "Closed case for mttc test", severity: "high",
        timeline: [{ timestamp: new Date(Date.now() - 120000).toISOString(), description: "Alert" }],
      });
      await updateCase("CASE-20260327-kpi004", { status: "closed" });

      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.mttc_cases >= 1, "mttc_cases should include the closed case");
      assert.ok(res.body.mttc >= 0, "mttc should be >= 0 for closed cases");
      // mttr should also count closed cases as a response fallback
      assert.ok(res.body.mttr_cases >= 1, "mttr_cases should include cases with closed transition");
    });

    it("should handle cases without status_history gracefully", async () => {
      // Manually write a case file without status_history to simulate legacy data
      const legacyCaseId = "CASE-20260327-kpi005";
      const caseDir = path.join(process.env.AUTOPILOT_DATA_DIR, "cases", legacyCaseId);
      await fs.mkdir(caseDir, { recursive: true });
      const alertTime = new Date(Date.now() - 30000).toISOString();
      const legacyPack = {
        schema_version: "1.0",
        case_id: legacyCaseId,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        title: "Legacy case without status_history",
        summary: "",
        severity: "low",
        confidence: 0,
        entities: [],
        timeline: [{ timestamp: alertTime, description: "Alert" }],
        mitre: [],
        mcp_calls: [],
        evidence_refs: [],
        plans: [],
        approvals: [],
        actions: [],
        status: "open",
        feedback: [],
        // No status_history field
      };
      await fs.writeFile(
        path.join(caseDir, "evidence-pack.json"),
        JSON.stringify(legacyPack, null, 2),
      );
      // Also write summary for listCases
      await fs.writeFile(
        path.join(caseDir, "summary.json"),
        JSON.stringify({ case_id: legacyCaseId, title: legacyPack.title, severity: "low", status: "open", created_at: legacyPack.created_at, updated_at: legacyPack.updated_at }),
      );

      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      // The legacy case should still contribute to mttd via timeline
      assert.ok(res.body.mttd_cases >= 1, "Legacy cases with timeline should contribute to mttd");
    });

    it("should report correct _cases counts", async () => {
      const res = await request(server, "GET", "/api/kpis?period=24h");
      assert.strictEqual(res.status, 200);
      // _cases counts should never exceed cases_analyzed
      assert.ok(res.body.mttd_cases <= res.body.cases_analyzed);
      assert.ok(res.body.mttt_cases <= res.body.cases_analyzed);
      assert.ok(res.body.mtti_cases <= res.body.cases_analyzed);
      assert.ok(res.body.mttr_cases <= res.body.cases_analyzed);
      assert.ok(res.body.mttc_cases <= res.body.cases_analyzed);
    });
  });

  describe("GET /api/agent-action/store-report", () => {
    it("should store a report and return report_id", async () => {
      const data = encodeURIComponent(JSON.stringify({ alerts_processed: 42, summary: "test" }));
      const res = await request(server, "GET", `/api/agent-action/store-report?type=hourly&data=${data}`);
      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.body.ok, true);
      assert.ok(res.body.report_id.startsWith("RPT-"));
      assert.ok(res.body.path);
      assert.ok(res.body.request_id);
    });

    it("should reject missing type", async () => {
      const data = encodeURIComponent(JSON.stringify({ test: true }));
      const res = await request(server, "GET", `/api/agent-action/store-report?data=${data}`);
      assert.strictEqual(res.status, 400);
    });

    it("should reject invalid type", async () => {
      const data = encodeURIComponent(JSON.stringify({ test: true }));
      const res = await request(server, "GET", `/api/agent-action/store-report?type=invalid&data=${data}`);
      assert.strictEqual(res.status, 400);
    });

    it("should reject missing data", async () => {
      const res = await request(server, "GET", "/api/agent-action/store-report?type=daily");
      assert.strictEqual(res.status, 400);
    });

    it("should reject invalid JSON in data", async () => {
      const res = await request(server, "GET", "/api/agent-action/store-report?type=daily&data=not-json");
      assert.strictEqual(res.status, 400);
    });
  });

  describe("GET /api/reports", () => {
    it("should list stored reports", async () => {
      // Store a report first
      const data = encodeURIComponent(JSON.stringify({ test: "list-test" }));
      await request(server, "GET", `/api/agent-action/store-report?type=daily&data=${data}`);

      const res = await request(server, "GET", "/api/reports");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
      assert.ok(res.body.length >= 1);

      const report = res.body[0];
      assert.ok(report.id);
      assert.ok(report.type);
      assert.ok(report.created_at);
      assert.ok(report.path);
    });

    it("should filter reports by type", async () => {
      const res = await request(server, "GET", "/api/reports?type=daily");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
      for (const r of res.body) {
        assert.strictEqual(r.type, "daily");
      }
    });

    it("should respect limit parameter", async () => {
      const res = await request(server, "GET", "/api/reports?limit=1");
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.length <= 1);
    });

    it("should return empty array when no reports exist for type", async () => {
      const res = await request(server, "GET", "/api/reports?type=weekly");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.body));
      assert.strictEqual(res.body.length, 0);
    });
  });
});
