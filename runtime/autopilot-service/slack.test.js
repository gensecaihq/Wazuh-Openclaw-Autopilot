/**
 * Tests for Slack pure functions
 *
 * Covers: escapeMrkdwn, isValidSlackUserId, getHelpMessage,
 * formatPlansMessage, getProposedPlanBlocks, getApprovedPlanBlocks,
 * getExecutingPlanBlocks, getExecutedPlanBlocks, getRejectedPlanBlocks.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  escapeMrkdwn,
  isValidSlackUserId,
  getHelpMessage,
  formatPlansMessage,
  getProposedPlanBlocks,
  getApprovedPlanBlocks,
  getExecutingPlanBlocks,
  getExecutedPlanBlocks,
  getRejectedPlanBlocks,
} = require("./slack");

// =============================================================================
// escapeMrkdwn
// =============================================================================

describe("escapeMrkdwn", () => {
  it("escapes & to &amp;", () => {
    assert.equal(escapeMrkdwn("a & b"), "a &amp; b");
  });

  it("escapes < to &lt;", () => {
    assert.equal(escapeMrkdwn("a < b"), "a &lt; b");
  });

  it("escapes > to &gt;", () => {
    assert.equal(escapeMrkdwn("a > b"), "a &gt; b");
  });

  it("escapes * with zero-width space", () => {
    assert.equal(escapeMrkdwn("*bold*"), "\u200B*bold\u200B*");
  });

  it("escapes _ with zero-width space", () => {
    assert.equal(escapeMrkdwn("_italic_"), "\u200B_italic\u200B_");
  });

  it("escapes backtick with zero-width space", () => {
    assert.equal(escapeMrkdwn("`code`"), "\u200B`code\u200B`");
  });

  it("escapes ~ with zero-width space", () => {
    assert.equal(escapeMrkdwn("~strike~"), "\u200B~strike\u200B~");
  });

  it("returns null for null input", () => {
    assert.equal(escapeMrkdwn(null), null);
  });

  it("returns undefined for undefined input", () => {
    assert.equal(escapeMrkdwn(undefined), undefined);
  });

  it("returns empty string for empty string", () => {
    assert.equal(escapeMrkdwn(""), "");
  });

  it("handles combined special characters", () => {
    const input = "<b>&\"test\"</b> *bold* _underline_ ~strike~ `code`";
    const result = escapeMrkdwn(input);
    // HTML entities are escaped
    assert.ok(result.includes("&lt;"));
    assert.ok(result.includes("&gt;"));
    assert.ok(result.includes("&amp;"));
    // Mrkdwn chars are prefixed with zero-width space
    assert.ok(result.includes("\u200B*"));
    assert.ok(result.includes("\u200B_"));
    assert.ok(result.includes("\u200B~"));
    assert.ok(result.includes("\u200B`"));
  });
});

// =============================================================================
// isValidSlackUserId
// =============================================================================

describe("isValidSlackUserId", () => {
  it("returns true for valid U-prefixed ID", () => {
    assert.equal(isValidSlackUserId("U12345ABC"), true);
  });

  it("returns true for valid W-prefixed ID", () => {
    assert.equal(isValidSlackUserId("W12345ABC"), true);
  });

  it("returns false for empty string", () => {
    assert.equal(isValidSlackUserId(""), false);
  });

  it("returns false for lowercase ID", () => {
    assert.equal(isValidSlackUserId("u12345abc"), false);
  });

  it("returns false for too-short ID (less than 9 chars)", () => {
    assert.equal(isValidSlackUserId("U1"), false);
    assert.equal(isValidSlackUserId("UA"), false);
    assert.equal(isValidSlackUserId("U1234"), false);
  });

  it("returns false for number input", () => {
    assert.equal(isValidSlackUserId(12345), false);
  });

  it("returns false for null input", () => {
    assert.equal(isValidSlackUserId(null), false);
  });
});

// =============================================================================
// getHelpMessage
// =============================================================================

describe("getHelpMessage", () => {
  it("returns valid structure with response_type and blocks array", () => {
    const msg = getHelpMessage();
    assert.equal(msg.response_type, "ephemeral");
    assert.ok(Array.isArray(msg.blocks));
    assert.ok(msg.blocks.length >= 2);
  });

  it("contains header and section block types", () => {
    const msg = getHelpMessage();
    const types = msg.blocks.map((b) => b.type);
    assert.ok(types.includes("header"));
    assert.ok(types.includes("section"));
  });
});

// =============================================================================
// formatPlansMessage
// =============================================================================

describe("formatPlansMessage", () => {
  it("returns text message for empty plans array", () => {
    const msg = formatPlansMessage([], "approved");
    assert.equal(msg.text, "No plans in 'approved' state.");
    assert.equal(msg.blocks, undefined);
  });

  it("returns blocks for non-empty plans array", () => {
    const plans = [
      {
        plan_id: "plan-001",
        title: "Block IP",
        risk_level: "high",
        actions: [{ type: "firewall_block", target: "10.0.0.1" }],
      },
    ];
    const msg = formatPlansMessage(plans, "proposed");
    assert.ok(Array.isArray(msg.blocks));
    assert.ok(msg.blocks.length >= 2);

    const header = msg.blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("proposed"));
  });
});

// =============================================================================
// getProposedPlanBlocks
// =============================================================================

describe("getProposedPlanBlocks", () => {
  const plan = {
    plan_id: "plan-100",
    case_id: "case-200",
    risk_level: "high",
    title: "Block malicious IP",
    description: "Firewall rule to block traffic from attacker IP",
    actions: [
      { type: "firewall_block", target: "10.0.0.99" },
      { type: "isolate_host", target: "srv-web-01" },
    ],
    expires_at: "2026-02-22T00:00:00Z",
  };

  it("contains approve and reject action buttons", () => {
    const blocks = getProposedPlanBlocks(plan);
    const actionsBlock = blocks.find((b) => b.type === "actions");
    assert.ok(actionsBlock, "actions block must exist");

    const actionIds = actionsBlock.elements.map((e) => e.action_id);
    assert.ok(actionIds.includes("approve_plan"));
    assert.ok(actionIds.includes("reject_plan"));
  });

  it("includes plan ID in button values", () => {
    const blocks = getProposedPlanBlocks(plan);
    const actionsBlock = blocks.find((b) => b.type === "actions");
    const approveBtn = actionsBlock.elements.find((e) => e.action_id === "approve_plan");
    assert.equal(approveBtn.value, "plan-100");
  });

  it("has header block with approval text", () => {
    const blocks = getProposedPlanBlocks(plan);
    const header = blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("Approval"));
  });

  it("shows risk level in uppercase", () => {
    const blocks = getProposedPlanBlocks(plan);
    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const riskField = fieldsBlock.fields.find((f) => f.text.includes("Risk Level"));
    assert.ok(riskField.text.includes("HIGH"));
  });
});

// =============================================================================
// getApprovedPlanBlocks
// =============================================================================

describe("getApprovedPlanBlocks", () => {
  const plan = {
    plan_id: "plan-100",
    case_id: "case-200",
    risk_level: "medium",
    actions: [{ type: "firewall_block", target: "10.0.0.99" }],
  };

  it("includes approver mention in fields", () => {
    const blocks = getApprovedPlanBlocks(plan, "U12345ABC");
    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const approverField = fieldsBlock.fields.find((f) => f.text.includes("Approved by"));
    assert.ok(approverField.text.includes("<@U12345ABC>"));
  });

  it("has execute and reject buttons", () => {
    const blocks = getApprovedPlanBlocks(plan, "U12345ABC");
    const actionsBlock = blocks.find((b) => b.type === "actions");
    const actionIds = actionsBlock.elements.map((e) => e.action_id);
    assert.ok(actionIds.includes("execute_plan"));
    assert.ok(actionIds.includes("reject_plan"));
  });

  it("execute button has confirm dialog", () => {
    const blocks = getApprovedPlanBlocks(plan, "U12345ABC");
    const actionsBlock = blocks.find((b) => b.type === "actions");
    const executeBtn = actionsBlock.elements.find((e) => e.action_id === "execute_plan");
    assert.ok(executeBtn.confirm, "execute button must have confirm dialog");
    assert.ok(executeBtn.confirm.title.text.includes("Confirm"));
  });
});

// =============================================================================
// getExecutingPlanBlocks
// =============================================================================

describe("getExecutingPlanBlocks", () => {
  it("contains plan ID and executor mention", () => {
    const blocks = getExecutingPlanBlocks("plan-100", "U99999ZZZZ", []);
    const sectionBlock = blocks.find((b) => b.type === "section" && b.text.text.includes("plan-100"));
    assert.ok(sectionBlock);
    assert.ok(sectionBlock.text.text.includes("<@U99999ZZZZ>"));
  });

  it("has Executing header", () => {
    const blocks = getExecutingPlanBlocks("plan-100", "U99999ZZZZ", []);
    const header = blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("Executing"));
  });

  it("includes action context when actions provided", () => {
    const actions = [
      { type: "block_ip", target: "10.0.0.1" },
      { type: "isolate_host", target: "srv-web-01" },
    ];
    const blocks = getExecutingPlanBlocks("plan-100", "U99999ZZZZ", actions);
    const actionBlock = blocks.find((b) => b.type === "section" && b.text.text.includes("Actions"));
    assert.ok(actionBlock);
    // After escapeMrkdwn, underscores are prefixed with zero-width space (\u200B)
    assert.ok(actionBlock.text.text.includes("block\u200B_ip"));
    assert.ok(actionBlock.text.text.includes("isolate\u200B_host"));
    assert.ok(actionBlock.text.text.includes("10.0.0.1"));
  });

  it("works without actions (backward compatible)", () => {
    const blocks = getExecutingPlanBlocks("plan-100", "U99999ZZZZ");
    assert.ok(Array.isArray(blocks));
    assert.ok(blocks.length >= 2);
  });
});

// =============================================================================
// getExecutedPlanBlocks
// =============================================================================

describe("getExecutedPlanBlocks", () => {
  it("reflects successful execution result", () => {
    const plan = {
      plan_id: "plan-100",
      case_id: "case-200",
      executed_at: "2026-02-21T12:00:00Z",
      execution_result: {
        success: true,
        actions_success: 2,
        actions_total: 2,
        results: [
          { status: "success", action_type: "firewall_block", target: "10.0.0.99" },
          { status: "success", action_type: "isolate_host", target: "srv-web-01" },
        ],
      },
    };
    const blocks = getExecutedPlanBlocks(plan, "UEXECUTOR1");
    const header = blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("Successfully"));

    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const resultField = fieldsBlock.fields.find((f) => f.text.includes("Result"));
    assert.ok(resultField.text.includes("2/2"));
  });

  it("reflects partial failure execution result", () => {
    const plan = {
      plan_id: "plan-101",
      case_id: "case-201",
      executed_at: "2026-02-21T13:00:00Z",
      execution_result: {
        success: false,
        actions_success: 1,
        actions_total: 2,
        results: [
          { status: "success", action_type: "firewall_block", target: "10.0.0.99" },
          { status: "failed", action_type: "isolate_host", target: "srv-web-01" },
        ],
      },
    };
    const blocks = getExecutedPlanBlocks(plan, "UEXECUTOR2");
    const header = blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("Failures"));

    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const resultField = fieldsBlock.fields.find((f) => f.text.includes("Result"));
    assert.ok(resultField.text.includes("1/2"));
  });
});

// =============================================================================
// getRejectedPlanBlocks
// =============================================================================

describe("getRejectedPlanBlocks", () => {
  it("includes rejector mention and rejection reason", () => {
    const plan = {
      plan_id: "plan-100",
      case_id: "case-200",
      rejection_reason: "Too risky for production",
    };
    const blocks = getRejectedPlanBlocks(plan, "UREJECTOR1");
    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const rejectorField = fieldsBlock.fields.find((f) => f.text.includes("Rejected by"));
    assert.ok(rejectorField.text.includes("<@UREJECTOR1>"));

    const reasonField = fieldsBlock.fields.find((f) => f.text.includes("Reason"));
    assert.ok(reasonField.text.includes("Too risky for production"));
  });

  it("has Plan Rejected header", () => {
    const plan = {
      plan_id: "plan-100",
      case_id: "case-200",
      rejection_reason: "Not needed",
    };
    const blocks = getRejectedPlanBlocks(plan, "UREJECTOR1");
    const header = blocks.find((b) => b.type === "header");
    assert.ok(header.text.text.includes("Rejected"));
  });

  it("shows fallback text when rejection_reason is empty", () => {
    const plan = {
      plan_id: "plan-100",
      case_id: "case-200",
      rejection_reason: "",
    };
    const blocks = getRejectedPlanBlocks(plan, "UREJECTOR1");
    const fieldsBlock = blocks.find((b) => b.type === "section" && b.fields);
    const reasonField = fieldsBlock.fields.find((f) => f.text.includes("Reason"));
    assert.ok(reasonField.text.includes("No reason provided"));
  });
});
