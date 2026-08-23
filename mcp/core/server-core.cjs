"use strict";

// MCP server core: protocol-level request handling independent of the stdio
// transport, so tests can drive it directly.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { Dispatcher } = require("./dispatch.cjs");

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_NAME = "cdn-node";
const SERVER_VERSION = require("../../package.json").version;

function toolCatalog() {
  return contracts.TOOL_LIST.map((tool) => ({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema,
    annotations: tool.annotations,
  }));
}

class ServerCore {
  constructor(ctx) {
    this.dispatcher = new Dispatcher(ctx);
  }

  handle(method, params = {}) {
    switch (method) {
      case "initialize":
        return {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        };
      case "ping":
        return {};
      case "tools/list":
        return { tools: toolCatalog() };
      case "tools/call": {
        const result = this.dispatcher.callTool(params.name, params.arguments ?? {});
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result,
          isError: result.status === "error",
        };
      }
      default:
        throw Object.assign(new Error(`method not found: ${method}`), { jsonrpcCode: -32601 });
    }
  }
}

module.exports = { ServerCore, SERVER_NAME, SERVER_VERSION, PROTOCOL_VERSION, toolCatalog };
