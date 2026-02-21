/**
 * Slack Integration for Wazuh Autopilot
 *
 * Provides:
 * - Socket Mode for secure, bidirectional communication
 * - Two-tier approval workflow (Approve -> Execute)
 * - Interactive buttons for approvals
 * - Case notifications and alerts
 * - Slash commands for manual operations
 */

const { App } = require("@slack/bolt");
const crypto = require("crypto");

// =============================================================================
// HELPERS
// =============================================================================

// Validate Slack user ID format (U or W prefix followed by alphanumeric)
function isValidSlackUserId(id) {
  return typeof id === "string" && /^[UW][A-Z0-9]+$/.test(id);
}

// Escape Slack mrkdwn special characters in user-controlled text
function escapeMrkdwn(text) {
  if (!text) return text;
  return String(text)
    .replace(/[&<>]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[ch]))
    .replace(/[*_~`]/g, (ch) => `\u200B${ch}`);
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const config = {
  appToken: process.env.SLACK_APP_TOKEN,
  botToken: process.env.SLACK_BOT_TOKEN,
  // Socket Mode doesn't use signing secret for verification, but Bolt requires it.
  // Generate a random value per process if not configured to avoid a static default.
  signingSecret: process.env.SLACK_SIGNING_SECRET || crypto.randomBytes(32).toString("hex"),
  alertsChannel: process.env.SLACK_ALERTS_CHANNEL,
  approvalsChannel: process.env.SLACK_APPROVALS_CHANNEL,
  reportsChannel: process.env.SLACK_REPORTS_CHANNEL,
};

// =============================================================================
// LOGGING
// =============================================================================

function log(level, component, msg, extra = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    component: `slack:${component}`,
    msg,
    ...extra,
  };
  console.log(JSON.stringify(entry));
}

// =============================================================================
// SLACK APP INITIALIZATION
// =============================================================================

let slackApp = null;
let isInitialized = false;

/**
 * Stop and clean up the Slack app
 * Issue #5 fix: Prevent memory leaks on reinitialization
 */
async function stopSlack() {
  if (slackApp) {
    try {
      await slackApp.stop();
      log("info", "cleanup", "Slack app stopped");
    } catch (err) {
      log("warn", "cleanup", "Error stopping Slack app", { error: err.message });
    }
    slackApp = null;
    isInitialized = false;
  }
}

/**
 * Initialize Slack integration
 * @param {Object} runtimeService - Reference to the main runtime service exports
 */
async function initSlack(runtimeService) {
  if (!config.appToken || !config.botToken) {
    log("info", "init", "Slack tokens not configured - Slack integration disabled");
    return null;
  }

  // Issue #5 fix: Clean up existing app before creating new one
  if (slackApp) {
    log("info", "init", "Stopping existing Slack app before reinitialization");
    await stopSlack();
  }

  try {
    slackApp = new App({
      token: config.botToken,
      appToken: config.appToken,
      socketMode: true,
    });

    // Warn about invalid channel ID formats
    const channelIdPattern = /^C[A-Z0-9]+$/;
    for (const [name, id] of Object.entries({
      alertsChannel: config.alertsChannel,
      approvalsChannel: config.approvalsChannel,
      reportsChannel: config.reportsChannel,
    })) {
      if (id && !channelIdPattern.test(id)) {
        log("warn", "init", `${name} value "${id}" does not match Slack channel ID format (C[A-Z0-9]+)`);
      }
    }

    // Register handlers
    registerSlashCommands(runtimeService);
    registerInteractiveButtons(runtimeService);

    // Start the app with a timeout to prevent hanging if Slack is unreachable
    const SLACK_INIT_TIMEOUT_MS = 30000;
    await Promise.race([
      slackApp.start(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Slack Socket Mode connection timed out")), SLACK_INIT_TIMEOUT_MS),
      ),
    ]);
    isInitialized = true;

    log("info", "init", "Slack Socket Mode connected successfully");
    return slackApp;
  } catch (err) {
    log("error", "init", "Failed to initialize Slack", { error: err.message });
    slackApp = null;
    isInitialized = false;
    return null;
  }
}

// =============================================================================
// SLASH COMMANDS
// =============================================================================

function registerSlashCommands(runtime) {
  if (!slackApp) return;

  // /wazuh command handler
  slackApp.command("/wazuh", async ({ command, ack, respond, client }) => {
    await ack();

    const args = command.text.split(" ");
    const subcommand = args[0]?.toLowerCase();
    const userId = command.user_id;

    if (!isValidSlackUserId(userId)) {
      await respond({ text: "Error: Invalid user ID in request", response_type: "ephemeral" });
      return;
    }

    try {
      switch (subcommand) {
        case "help":
          await respond(getHelpMessage());
          break;

        case "status": {
          const status = runtime.getResponderStatus();
          await respond({
            response_type: "ephemeral",
            text: `Responder Status: ${status.enabled ? "ENABLED" : "DISABLED"}\n${status.message}`,
          });
          break;
        }

        case "plans": {
          const state = args[1] || "approved";
          const plans = runtime.listPlans({ state, limit: 10 });
          await respond(formatPlansMessage(plans, state));
          break;
        }

        case "approve": {
          const planIdApprove = args[1];
          if (!planIdApprove) {
            await respond({ text: "Usage: /wazuh approve <plan_id>" });
            return;
          }
          try {
            const approvedPlan = runtime.approvePlan(planIdApprove, userId, "Approved via Slack");
            await respond({
              text: `Plan ${planIdApprove} APPROVED (Tier 1 complete).\nReady for execution. Use /wazuh execute ${planIdApprove} or click the Execute button.`,
            });
            // Post to approvals channel
            if (config.approvalsChannel) {
              await postApprovalNotification(client, approvedPlan, userId, "approved");
            }
          } catch (err) {
            await respond({ text: `Error: ${err.message}` });
          }
          break;
        }

        case "execute": {
          const planIdExecute = args[1];
          if (!planIdExecute) {
            await respond({ text: "Usage: /wazuh execute <plan_id>" });
            return;
          }
          try {
            const executedPlan = await runtime.executePlan(planIdExecute, userId);
            await respond({
              text: `Plan ${planIdExecute} EXECUTED.\nResult: ${executedPlan.execution_result.success ? "SUCCESS" : "PARTIAL FAILURE"}\nActions: ${executedPlan.execution_result.actions_success}/${executedPlan.execution_result.actions_total} succeeded`,
            });
            // Post execution notification
            if (config.approvalsChannel) {
              await postExecutionNotification(client, executedPlan, userId);
            }
          } catch (err) {
            await respond({ text: `Error: ${err.message}` });
          }
          break;
        }

        case "reject": {
          const planIdReject = args[1];
          const reason = args.slice(2).join(" ") || "Rejected via Slack";
          if (!planIdReject) {
            await respond({ text: "Usage: /wazuh reject <plan_id> [reason]" });
            return;
          }
          try {
            const rejectedPlan = runtime.rejectPlan(planIdReject, userId, reason);
            await respond({ text: `Plan ${planIdReject} REJECTED.\nReason: ${reason}` });
            if (config.approvalsChannel) {
              await postApprovalNotification(client, rejectedPlan, userId, "rejected");
            }
          } catch (err) {
            await respond({ text: `Error: ${err.message}` });
          }
          break;
        }

        default:
          await respond(getHelpMessage());
      }
    } catch (err) {
      log("error", "command", "Slash command error", { error: err.message, subcommand });
      await respond({ text: `Error: ${err.message}` });
    }
  });
}

// =============================================================================
// INTERACTIVE BUTTONS
// =============================================================================

function registerInteractiveButtons(runtime) {
  if (!slackApp) return;

  // Tier 1: Approve button
  slackApp.action("approve_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const planId = body.actions[0].value;
    const userId = body.user.id;

    if (!isValidSlackUserId(userId)) {
      await respond({ text: "Error: Invalid user ID", response_type: "ephemeral" });
      return;
    }

    try {
      const plan = runtime.approvePlan(planId, userId, "Approved via Slack button");

      // Update the original message
      await client.chat.update({
        channel: body.channel.id,
        ts: body.message.ts,
        blocks: getApprovedPlanBlocks(plan, userId),
        text: `Plan ${planId} approved by <@${userId}>`,
      });

      // Post notification
      if (config.approvalsChannel && config.approvalsChannel !== body.channel.id) {
        await postApprovalNotification(client, plan, userId, "approved");
      }

      log("info", "button", "Plan approved via button", { plan_id: planId, user_id: userId });
    } catch (err) {
      await respond({ text: `Error approving plan: ${err.message}`, response_type: "ephemeral" });
    }
  });

  // Tier 2: Execute button
  slackApp.action("execute_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const planId = body.actions[0].value;
    const userId = body.user.id;

    if (!isValidSlackUserId(userId)) {
      await respond({ text: "Error: Invalid user ID", response_type: "ephemeral" });
      return;
    }

    try {
      // Show executing status
      await client.chat.update({
        channel: body.channel.id,
        ts: body.message.ts,
        blocks: getExecutingPlanBlocks(planId, userId),
        text: `Plan ${planId} executing...`,
      });

      const plan = await runtime.executePlan(planId, userId);

      // Update with result
      await client.chat.update({
        channel: body.channel.id,
        ts: body.message.ts,
        blocks: getExecutedPlanBlocks(plan, userId),
        text: `Plan ${planId} executed by <@${userId}>`,
      });

      // Post notification
      if (config.approvalsChannel && config.approvalsChannel !== body.channel.id) {
        await postExecutionNotification(client, plan, userId);
      }

      log("info", "button", "Plan executed via button", {
        plan_id: planId,
        user_id: userId,
        success: plan.execution_result.success,
      });
    } catch (err) {
      // Revert to approved state message on error
      await respond({ text: `Error executing plan: ${err.message}`, response_type: "ephemeral" });
    }
  });

  // Reject button
  slackApp.action("reject_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const planId = body.actions[0].value;
    const userId = body.user.id;

    if (!isValidSlackUserId(userId)) {
      await respond({ text: "Error: Invalid user ID", response_type: "ephemeral" });
      return;
    }

    try {
      const plan = runtime.rejectPlan(planId, userId, "Rejected via Slack button");

      await client.chat.update({
        channel: body.channel.id,
        ts: body.message.ts,
        blocks: getRejectedPlanBlocks(plan, userId),
        text: `Plan ${planId} rejected by <@${userId}>`,
      });

      log("info", "button", "Plan rejected via button", { plan_id: planId, user_id: userId });
    } catch (err) {
      await respond({ text: `Error rejecting plan: ${err.message}`, response_type: "ephemeral" });
    }
  });
}

// =============================================================================
// MESSAGE FORMATTERS
// =============================================================================

function getHelpMessage() {
  return {
    response_type: "ephemeral",
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: "Wazuh Autopilot Commands" },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: "*Two-Tier Approval Workflow:*\n" +
            "1. Plans are created in `proposed` state\n" +
            "2. *Tier 1 (Approve):* Human reviews and approves\n" +
            "3. *Tier 2 (Execute):* Human explicitly triggers execution\n",
        },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: "*Available Commands:*\n" +
            "`/wazuh status` - Check responder status\n" +
            "`/wazuh plans [state]` - List plans (proposed/approved/completed)\n" +
            "`/wazuh approve <plan_id>` - Approve a plan (Tier 1)\n" +
            "`/wazuh execute <plan_id>` - Execute a plan (Tier 2)\n" +
            "`/wazuh reject <plan_id> [reason]` - Reject a plan\n" +
            "`/wazuh help` - Show this message",
        },
      },
    ],
  };
}

function formatPlansMessage(plans, state) {
  if (plans.length === 0) {
    return { text: `No plans in '${state}' state.` };
  }

  const planList = plans.map((p) => {
    return `• \`${p.plan_id}\` - ${p.title} (${p.risk_level} risk) - ${p.actions.length} actions`;
  }).join("\n");

  return {
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `Plans (${state})` },
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: planList },
      },
    ],
  };
}

// =============================================================================
// PLAN APPROVAL BLOCKS
// =============================================================================

/**
 * Generate Slack blocks for a new plan requiring approval
 */
function getProposedPlanBlocks(plan) {
  const actionsText = plan.actions.map((a) => `• ${escapeMrkdwn(a.type)}: ${escapeMrkdwn(a.target)}`).join("\n");

  return [
    {
      type: "header",
      text: { type: "plain_text", text: "Response Plan Requires Approval" },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${plan.case_id}` },
        { type: "mrkdwn", text: `*Risk Level:*\n${plan.risk_level.toUpperCase()}` },
        { type: "mrkdwn", text: `*Actions:*\n${plan.actions.length}` },
      ],
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Title:* ${escapeMrkdwn(plan.title)}\n\n*Description:*\n${escapeMrkdwn(plan.description) || "_No description_"}` },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Proposed Actions:*\n${actionsText}` },
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: `Expires: <!date^${Math.floor(new Date(plan.expires_at).getTime() / 1000)}^{date_short_pretty} at {time}|${plan.expires_at}>` },
      ],
    },
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "Approve (Tier 1)" },
          style: "primary",
          action_id: "approve_plan",
          value: plan.plan_id,
        },
        {
          type: "button",
          text: { type: "plain_text", text: "Reject" },
          style: "danger",
          action_id: "reject_plan",
          value: plan.plan_id,
        },
      ],
    },
  ];
}

function getApprovedPlanBlocks(plan, approverId) {
  const actionsText = plan.actions.map((a) => `• ${escapeMrkdwn(a.type)}: ${escapeMrkdwn(a.target)}`).join("\n");

  return [
    {
      type: "header",
      text: { type: "plain_text", text: "Plan Approved - Ready for Execution" },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${plan.case_id}` },
        { type: "mrkdwn", text: `*Risk Level:*\n${plan.risk_level.toUpperCase()}` },
        { type: "mrkdwn", text: `*Approved by:*\n<@${approverId}>` },
      ],
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Actions to Execute:*\n${actionsText}` },
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: "Tier 1 (Approval) complete. Click Execute to trigger actions." },
      ],
    },
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "Execute (Tier 2)" },
          style: "primary",
          action_id: "execute_plan",
          value: plan.plan_id,
          confirm: {
            title: { type: "plain_text", text: "Confirm Execution" },
            text: { type: "mrkdwn", text: `This will execute ${plan.actions.length} response action(s). This action cannot be undone.` },
            confirm: { type: "plain_text", text: "Execute" },
            deny: { type: "plain_text", text: "Cancel" },
          },
        },
        {
          type: "button",
          text: { type: "plain_text", text: "Reject" },
          style: "danger",
          action_id: "reject_plan",
          value: plan.plan_id,
        },
      ],
    },
  ];
}

function getExecutingPlanBlocks(planId, executorId) {
  return [
    {
      type: "header",
      text: { type: "plain_text", text: "Executing Plan..." },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `Plan \`${planId}\` is being executed by <@${executorId}>...` },
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: "Please wait while actions are being executed." },
      ],
    },
  ];
}

function getExecutedPlanBlocks(plan, executorId) {
  const result = plan.execution_result || {};
  const statusEmoji = result.success ? ":white_check_mark:" : ":warning:";
  const statusText = result.success ? "All Actions Completed Successfully" : "Execution Completed with Failures";

  const resultsText = (result.results || []).map((r) => {
    const emoji = r.status === "success" ? ":white_check_mark:" : ":x:";
    return `${emoji} ${r.action_type}: ${r.target} - ${r.status}`;
  }).join("\n");

  return [
    {
      type: "header",
      text: { type: "plain_text", text: `${statusEmoji} ${statusText}` },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${plan.case_id}` },
        { type: "mrkdwn", text: `*Executed by:*\n<@${executorId}>` },
        { type: "mrkdwn", text: `*Result:*\n${result.actions_success || 0}/${result.actions_total || 0} succeeded` },
      ],
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Action Results:*\n${resultsText}` },
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: `Executed at <!date^${Math.floor(new Date(plan.executed_at).getTime() / 1000)}^{date_short_pretty} at {time}|${plan.executed_at}>` },
      ],
    },
  ];
}

function getRejectedPlanBlocks(plan, rejectorId) {
  return [
    {
      type: "header",
      text: { type: "plain_text", text: ":x: Plan Rejected" },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${plan.case_id}` },
        { type: "mrkdwn", text: `*Rejected by:*\n<@${rejectorId}>` },
        { type: "mrkdwn", text: `*Reason:*\n${plan.rejection_reason || "_No reason provided_"}` },
      ],
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: "This plan will not be executed." },
      ],
    },
  ];
}

// =============================================================================
// NOTIFICATION FUNCTIONS
// =============================================================================

/**
 * Post a new plan for approval to the approvals channel
 */
async function postPlanForApproval(plan) {
  if (!slackApp || !config.approvalsChannel) {
    log("warn", "notify", "Cannot post approval - Slack not configured");
    return null;
  }

  try {
    const result = await slackApp.client.chat.postMessage({
      channel: config.approvalsChannel,
      blocks: getProposedPlanBlocks(plan),
      text: `New response plan requires approval: ${plan.plan_id}`,
    });

    log("info", "notify", "Posted plan for approval", { plan_id: plan.plan_id, channel: config.approvalsChannel });
    return result;
  } catch (err) {
    log("error", "notify", "Failed to post plan for approval", { error: err.message, plan_id: plan.plan_id });
    return null;
  }
}

/**
 * Post approval notification
 */
async function postApprovalNotification(client, plan, userId, action) {
  if (!config.approvalsChannel) return;

  const emoji = action === "approved" ? ":white_check_mark:" : ":x:";
  const text = `${emoji} Plan \`${plan.plan_id}\` ${action} by <@${userId}>`;

  try {
    await client.chat.postMessage({
      channel: config.approvalsChannel,
      text,
    });
  } catch (err) {
    log("error", "notify", "Failed to post approval notification", { error: err.message });
  }
}

/**
 * Post execution notification
 */
async function postExecutionNotification(client, plan, userId) {
  if (!config.approvalsChannel) return;

  const result = plan.execution_result;
  const emoji = result.success ? ":rocket:" : ":warning:";
  const status = result.success ? "completed successfully" : "completed with failures";

  try {
    await client.chat.postMessage({
      channel: config.approvalsChannel,
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `${emoji} *Plan Executed*\n` +
              `Plan \`${plan.plan_id}\` ${status}\n` +
              `Executed by <@${userId}>\n` +
              `Result: ${result.actions_success}/${result.actions_total} actions succeeded`,
          },
        },
      ],
      text: `Plan ${plan.plan_id} executed by <@${userId}>`,
    });
  } catch (err) {
    log("error", "notify", "Failed to post execution notification", { error: err.message });
  }
}

/**
 * Post case alert notification
 */
async function postCaseAlert(caseData) {
  if (!slackApp || !config.alertsChannel) return null;

  const severityEmoji = {
    critical: ":rotating_light:",
    high: ":warning:",
    medium: ":large_yellow_circle:",
    low: ":large_blue_circle:",
    informational: ":information_source:",
  };

  const emoji = severityEmoji[caseData.severity] || ":bell:";
  const entitiesText = caseData.entities.slice(0, 5).map((e) => `• ${e.type}: ${e.value}`).join("\n");

  try {
    const result = await slackApp.client.chat.postMessage({
      channel: config.alertsChannel,
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: `${emoji} ${caseData.title}` },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Case ID:*\n\`${caseData.case_id}\`` },
            { type: "mrkdwn", text: `*Severity:*\n${caseData.severity.toUpperCase()}` },
          ],
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Summary:*\n${caseData.summary}` },
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Entities:*\n${entitiesText || "_None extracted_"}` },
        },
        {
          type: "context",
          elements: [
            { type: "mrkdwn", text: `Created at <!date^${Math.floor(new Date(caseData.created_at).getTime() / 1000)}^{date_short_pretty} at {time}|${caseData.created_at}>` },
          ],
        },
      ],
      text: `${emoji} New case: ${caseData.case_id} - ${caseData.title}`,
    });

    log("info", "notify", "Posted case alert", { case_id: caseData.case_id, channel: config.alertsChannel });
    return result;
  } catch (err) {
    log("error", "notify", "Failed to post case alert", { error: err.message, case_id: caseData.case_id });
    return null;
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  initSlack,
  stopSlack,
  postPlanForApproval,
  postCaseAlert,
  postApprovalNotification,
  postExecutionNotification,
  isInitialized: () => isInitialized,
  // Pure functions (exported for testing)
  escapeMrkdwn,
  isValidSlackUserId,
  getHelpMessage,
  formatPlansMessage,
  getProposedPlanBlocks,
  getApprovedPlanBlocks,
  getExecutingPlanBlocks,
  getExecutedPlanBlocks,
  getRejectedPlanBlocks,
};
