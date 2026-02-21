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

// Validate Slack user ID format (U or W prefix followed by 8+ alphanumeric chars)
function isValidSlackUserId(id) {
  return typeof id === "string" && /^[UW][A-Z0-9]{8,}$/.test(id);
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
    let initTimeoutId;
    try {
      await Promise.race([
        slackApp.start(),
        new Promise((_, reject) => {
          initTimeoutId = setTimeout(() => reject(new Error("Slack Socket Mode connection timed out")), SLACK_INIT_TIMEOUT_MS);
        }),
      ]);
      clearTimeout(initTimeoutId);
    } catch (startErr) {
      clearTimeout(initTimeoutId);
      // If timeout won, stop the partially-connected app to prevent resource leaks
      if (slackApp) {
        await slackApp.stop().catch(() => {});
      }
      throw startErr;
    }
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
      try {
        await respond({ text: `Error: ${safeErrorMessage(err)}` });
      } catch (respondErr) {
        log("error", "command", "Failed to send error response", { error: respondErr.message });
      }
    }
  });
}

// =============================================================================
// INTERACTIVE BUTTONS
// =============================================================================

// Validate and extract action payload fields safely
function validateActionPayload(body) {
  if (!Array.isArray(body.actions) || body.actions.length === 0) {
    return { valid: false, error: "Invalid interaction payload" };
  }
  const planId = body.actions[0].value;
  if (typeof planId !== "string" || !/^PLAN-\d+-[a-f0-9]{8}$/.test(planId)) {
    return { valid: false, error: "Invalid plan ID format" };
  }
  const userId = body.user?.id;
  if (!isValidSlackUserId(userId)) {
    return { valid: false, error: "Invalid user ID" };
  }
  const channelId = body.channel?.id;
  const messageTs = body.message?.ts;
  return { valid: true, planId, userId, channelId, messageTs };
}

// Sanitize error messages before sending to Slack
const SAFE_ERROR_PATTERNS = [
  /^Plan not found/,
  /^Cannot (approve|reject|execute) plan/,
  /^Plan has expired/,
  /^Tier 1 required/,
  /^Plan is already being executed/,
  /^Cannot reject plan that is currently executing/,
  /^Responder capability is DISABLED/,
  /^Concurrent execution limit/,
];

function safeErrorMessage(err) {
  if (SAFE_ERROR_PATTERNS.some((re) => re.test(err.message))) {
    return err.message;
  }
  return "An internal error occurred. Check logs for details.";
}

function registerInteractiveButtons(runtime) {
  if (!slackApp) return;

  // Tier 1: Approve button
  slackApp.action("approve_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const payload = validateActionPayload(body);
    if (!payload.valid) {
      await respond({ text: `Error: ${payload.error}`, response_type: "ephemeral" });
      return;
    }

    try {
      const plan = runtime.approvePlan(payload.planId, payload.userId, "Approved via Slack button");

      // Update the original message (only if we have channel context)
      if (payload.channelId && payload.messageTs) {
        try {
          await client.chat.update({
            channel: payload.channelId,
            ts: payload.messageTs,
            blocks: getApprovedPlanBlocks(plan, payload.userId),
            text: `Plan ${payload.planId} approved by <@${payload.userId}>`,
          });
        } catch (updateErr) {
          log("warn", "button", "Failed to update message after approval", { error: updateErr.message });
        }
      }

      // Post notification
      if (config.approvalsChannel && config.approvalsChannel !== payload.channelId) {
        await postApprovalNotification(client, plan, payload.userId, "approved");
      }

      log("info", "button", "Plan approved via button", { plan_id: payload.planId, user_id: payload.userId });
    } catch (err) {
      try {
        await respond({ text: `Error: ${safeErrorMessage(err)}`, response_type: "ephemeral" });
      } catch (respondErr) {
        log("error", "button", "Failed to send error response", { error: respondErr.message, originalError: err.message });
      }
    }
  });

  // Tier 2: Execute button
  slackApp.action("execute_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const payload = validateActionPayload(body);
    if (!payload.valid) {
      await respond({ text: `Error: ${payload.error}`, response_type: "ephemeral" });
      return;
    }

    try {
      // Get plan details to show action context during execution
      const planDetails = runtime.getPlan(payload.planId);
      const planActions = planDetails && Array.isArray(planDetails.actions) ? planDetails.actions : [];

      // Show executing status with action context (only if we have channel context)
      if (payload.channelId && payload.messageTs) {
        try {
          await client.chat.update({
            channel: payload.channelId,
            ts: payload.messageTs,
            blocks: getExecutingPlanBlocks(payload.planId, payload.userId, planActions),
            text: `Plan ${payload.planId} executing...`,
          });
        } catch (updateErr) {
          log("warn", "button", "Failed to update message to executing state", { error: updateErr.message });
        }
      }

      let plan;
      try {
        plan = await runtime.executePlan(payload.planId, payload.userId);
      } catch (execErr) {
        // Execution failed — update message to show failure instead of leaving "Executing" stuck
        if (payload.channelId && payload.messageTs) {
          try {
            await client.chat.update({
              channel: payload.channelId,
              ts: payload.messageTs,
              blocks: [{
                type: "header",
                text: { type: "plain_text", text: ":x: Plan Execution Failed" },
              }, {
                type: "section",
                text: { type: "mrkdwn", text: `Plan \`${payload.planId}\` failed: ${escapeMrkdwn(safeErrorMessage(execErr))}` },
              }],
              text: `Plan ${payload.planId} execution failed`,
            });
          } catch (msgErr) {
            log("warn", "button", "Failed to update message after execution failure", { error: msgErr.message });
          }
        }
        throw execErr;
      }

      // Update with result
      if (payload.channelId && payload.messageTs) {
        try {
          await client.chat.update({
            channel: payload.channelId,
            ts: payload.messageTs,
            blocks: getExecutedPlanBlocks(plan, payload.userId),
            text: `Plan ${payload.planId} executed by <@${payload.userId}>`,
          });
        } catch (updateErr) {
          log("warn", "button", "Failed to update message with execution result", { error: updateErr.message });
        }
      }

      // Post notification
      if (config.approvalsChannel && config.approvalsChannel !== payload.channelId) {
        await postExecutionNotification(client, plan, payload.userId);
      }

      const execResult = plan.execution_result || {};
      log("info", "button", "Plan executed via button", {
        plan_id: payload.planId,
        user_id: payload.userId,
        success: execResult.success,
      });
    } catch (err) {
      try {
        await respond({ text: `Error: ${safeErrorMessage(err)}`, response_type: "ephemeral" });
      } catch (respondErr) {
        log("error", "button", "Failed to send error response", { error: respondErr.message, originalError: err.message });
      }
    }
  });

  // Reject button
  slackApp.action("reject_plan", async ({ body, ack, client, respond }) => {
    await ack();

    const payload = validateActionPayload(body);
    if (!payload.valid) {
      await respond({ text: `Error: ${payload.error}`, response_type: "ephemeral" });
      return;
    }

    try {
      const plan = runtime.rejectPlan(payload.planId, payload.userId, "Rejected via Slack button");

      if (payload.channelId && payload.messageTs) {
        try {
          await client.chat.update({
            channel: payload.channelId,
            ts: payload.messageTs,
            blocks: getRejectedPlanBlocks(plan, payload.userId),
            text: `Plan ${payload.planId} rejected by <@${payload.userId}>`,
          });
        } catch (updateErr) {
          log("warn", "button", "Failed to update message after rejection", { error: updateErr.message });
        }
      }

      log("info", "button", "Plan rejected via button", { plan_id: payload.planId, user_id: payload.userId });
    } catch (err) {
      try {
        await respond({ text: `Error: ${safeErrorMessage(err)}`, response_type: "ephemeral" });
      } catch (respondErr) {
        log("error", "button", "Failed to send error response", { error: respondErr.message, originalError: err.message });
      }
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

// Truncate text to fit Slack's 3000-char mrkdwn limit
const MAX_MRKDWN_LENGTH = 2900;
const MAX_ACTIONS_DISPLAY = 20;
const MAX_HEADER_LENGTH = 150;

function truncateActionsText(actions, formatter) {
  const displayed = actions.slice(0, MAX_ACTIONS_DISPLAY);
  let text = displayed.map(formatter).join("\n");
  if (actions.length > MAX_ACTIONS_DISPLAY) {
    text += `\n_...and ${actions.length - MAX_ACTIONS_DISPLAY} more_`;
  }
  if (text.length > MAX_MRKDWN_LENGTH) {
    text = text.substring(0, MAX_MRKDWN_LENGTH) + "\n_...truncated_";
  }
  return text;
}

function safeHeader(text) {
  return text.substring(0, MAX_HEADER_LENGTH);
}

function formatPlansMessage(plans, state) {
  if (plans.length === 0) {
    return { text: `No plans in '${state}' state.` };
  }

  const planList = plans.map((p) => {
    const actionCount = Array.isArray(p.actions) ? p.actions.length : 0;
    return `• \`${p.plan_id}\` - ${p.title} (${p.risk_level} risk) - ${actionCount} actions`;
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
  const actions = Array.isArray(plan.actions) ? plan.actions : [];
  const actionsText = truncateActionsText(actions, (a) => `• ${escapeMrkdwn(a.type)}: ${escapeMrkdwn(a.target)}`);

  return [
    {
      type: "header",
      text: { type: "plain_text", text: safeHeader("Response Plan Requires Approval") },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${escapeMrkdwn(plan.case_id)}` },
        { type: "mrkdwn", text: `*Risk Level:*\n${(plan.risk_level || "unknown").toUpperCase()}` },
        { type: "mrkdwn", text: `*Actions:*\n${actions.length}` },
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
  const actions = Array.isArray(plan.actions) ? plan.actions : [];
  const actionsText = truncateActionsText(actions, (a) => `• ${escapeMrkdwn(a.type)}: ${escapeMrkdwn(a.target)}`);

  return [
    {
      type: "header",
      text: { type: "plain_text", text: safeHeader("Plan Approved - Ready for Execution") },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${escapeMrkdwn(plan.case_id)}` },
        { type: "mrkdwn", text: `*Risk Level:*\n${(plan.risk_level || "unknown").toUpperCase()}` },
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
            text: { type: "mrkdwn", text: `This will execute ${actions.length} response action(s). This action cannot be undone.` },
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

function getExecutingPlanBlocks(planId, executorId, actions) {
  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: "Executing Plan..." },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `Plan \`${planId}\` is being executed by <@${executorId}>...` },
    },
  ];

  // Preserve action context so the user can see what's being executed
  if (Array.isArray(actions) && actions.length > 0) {
    const actionList = truncateActionsText(actions, (a) => `:hourglass_flowing_sand: \`${escapeMrkdwn(a.type)}\` → ${escapeMrkdwn(a.target)}`);
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Actions (${actions.length}):*\n${actionList}` },
    });
  }

  blocks.push({
    type: "context",
    elements: [
      { type: "mrkdwn", text: "Please wait while actions are being executed." },
    ],
  });

  return blocks;
}

function getExecutedPlanBlocks(plan, executorId) {
  const result = plan.execution_result || {};
  const statusEmoji = result.success ? ":white_check_mark:" : ":warning:";
  const statusText = result.success ? "All Actions Completed Successfully" : "Execution Completed with Failures";

  const resultsText = truncateActionsText(result.results || [], (r) => {
    const emoji = r.status === "success" ? ":white_check_mark:" : ":x:";
    return `${emoji} ${escapeMrkdwn(r.action_type)}: ${escapeMrkdwn(r.target)} - ${r.status}`;
  });

  return [
    {
      type: "header",
      text: { type: "plain_text", text: safeHeader(`${statusEmoji} ${statusText}`) },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Plan ID:*\n\`${plan.plan_id}\`` },
        { type: "mrkdwn", text: `*Case:*\n${escapeMrkdwn(plan.case_id)}` },
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
        { type: "mrkdwn", text: `*Case:*\n${escapeMrkdwn(plan.case_id)}` },
        { type: "mrkdwn", text: `*Rejected by:*\n<@${rejectorId}>` },
        { type: "mrkdwn", text: `*Reason:*\n${escapeMrkdwn(plan.rejection_reason) || "_No reason provided_"}` },
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

  const result = plan.execution_result || {};
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
              `Result: ${result.actions_success || 0}/${result.actions_total || 0} actions succeeded`,
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
  const entities = Array.isArray(caseData.entities) ? caseData.entities : [];
  const entitiesText = entities.slice(0, 5).map((e) => `• ${escapeMrkdwn(e.type)}: ${escapeMrkdwn(e.value)}`).join("\n");

  try {
    const result = await slackApp.client.chat.postMessage({
      channel: config.alertsChannel,
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: safeHeader(`${emoji} ${caseData.title}`) },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Case ID:*\n\`${caseData.case_id}\`` },
            { type: "mrkdwn", text: `*Severity:*\n${(caseData.severity || "unknown").toUpperCase()}` },
          ],
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Summary:*\n${escapeMrkdwn(caseData.summary)}` },
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
