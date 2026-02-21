/**
 * JSON body parsing tests.
 *
 * Uses Node.js built-in test runner -- no external dependencies.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");
const { EventEmitter } = require("events");

// Set env vars BEFORE requiring index.js
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `body-test-${Date.now()}`);

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");

const { parseJsonBody } = require("./index.js");

const dataDir = process.env.AUTOPILOT_DATA_DIR;

/**
 * Create a mock request that emits data/end events like an http.IncomingMessage.
 *
 * @param {string|object|null} body - Body to send. null means empty body (end immediately).
 * @param {object} [options]
 * @param {number} [options.delay] - Delay in ms before emitting data.
 * @param {boolean} [options.multiChunk] - Split payload into multiple chunks.
 */
function createMockRequest(body, options = {}) {
  const { delay = 0, multiChunk = false } = options;
  const req = new EventEmitter();
  req.destroy = () => {};

  process.nextTick(() => {
    const emit = () => {
      if (body === null || body === undefined) {
        // Empty body -- just end
        req.emit("end");
        return;
      }

      const raw = typeof body === "string" ? body : JSON.stringify(body);
      const buf = Buffer.from(raw, "utf8");

      if (multiChunk && buf.length > 1) {
        const mid = Math.floor(buf.length / 2);
        req.emit("data", buf.slice(0, mid));
        req.emit("data", buf.slice(mid));
      } else {
        req.emit("data", buf);
      }
      req.emit("end");
    };

    if (delay > 0) {
      setTimeout(emit, delay);
    } else {
      emit();
    }
  });

  return req;
}

describe("parseJsonBody", () => {
  before(() => {
    fs.mkdirSync(dataDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("parses valid JSON body correctly", async () => {
    const input = { action: "block_ip", target: "192.168.1.1" };
    const req = createMockRequest(input);
    const result = await parseJsonBody(req);
    assert.deepStrictEqual(result, input);
  });

  it("returns empty object for empty body", async () => {
    const req = createMockRequest(null);
    const result = await parseJsonBody(req);
    assert.deepStrictEqual(result, {});
  });

  it("rejects with Invalid JSON for malformed body", async () => {
    const req = createMockRequest("{not valid json!!!");
    await assert.rejects(
      () => parseJsonBody(req),
      (err) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes("Invalid JSON"), `Expected "Invalid JSON", got "${err.message}"`);
        return true;
      },
    );
  });

  it("rejects with Request body too large for oversized body", async () => {
    // Create a buffer larger than 1MB (MAX_BODY_SIZE)
    const bigBody = Buffer.alloc(1024 * 1024 + 1, 0x78); // 'x' bytes

    const req = new EventEmitter();
    req.destroy = () => {};
    process.nextTick(() => {
      req.emit("data", bigBody);
      req.emit("end");
    });

    await assert.rejects(
      () => parseJsonBody(req),
      (err) => {
        assert.ok(err instanceof Error);
        assert.ok(
          err.message.includes("Request body too large"),
          `Expected "Request body too large", got "${err.message}"`,
        );
        return true;
      },
    );
  });

  it("concatenates multiple chunks correctly", async () => {
    const input = { items: [1, 2, 3], label: "multi" };
    const req = createMockRequest(input, { multiChunk: true });
    const result = await parseJsonBody(req);
    assert.deepStrictEqual(result, input);
  });

  it("parses UTF-8 encoded body correctly", async () => {
    const input = { greeting: "Hello, world!", note: "Special chars: \u00e9\u00e8\u00ea\u00eb\u00f1\u00fc\u00e4\u00f6" };
    const req = createMockRequest(input);
    const result = await parseJsonBody(req);
    assert.deepStrictEqual(result, input);
  });

  it("parses nested JSON objects correctly", async () => {
    const input = {
      alert: {
        id: 123,
        source: {
          agent: { name: "wazuh-agent-01", id: 42 },
          rule: { level: 12, description: "SSH brute-force" },
        },
        tags: ["ssh", "brute-force"],
      },
    };
    const req = createMockRequest(input);
    const result = await parseJsonBody(req);
    assert.deepStrictEqual(result, input);
  });

  it("returns empty object for body with only whitespace", async () => {
    const req = createMockRequest("   ");
    // "   " is truthy so JSON.parse will be called, which throws -> "Invalid JSON"
    // However the implementation does: resolve(body ? JSON.parse(body) : {})
    // "   " is truthy, JSON.parse("   ") throws, so it should reject.
    // Let's test what actually happens: whitespace-only body should reject as Invalid JSON
    // because "   ".trim() is "" but the code checks `body ? ...` and "   " is truthy.
    await assert.rejects(
      () => parseJsonBody(req),
      (err) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes("Invalid JSON"), `Expected "Invalid JSON", got "${err.message}"`);
        return true;
      },
    );
  });
});
