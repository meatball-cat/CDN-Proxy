"use strict";

// Minimal line-delimited JSON-RPC 2.0 transport for the local stdio MCP
// server. No network module is imported anywhere in this process.

function startStdioTransport(core, { input = process.stdin, output = process.stdout } = {}) {
  let buffer = "";
  input.setEncoding("utf8");
  input.on("data", (chunk) => {
    buffer += chunk;
    let newlineIndex;
    while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (line.length === 0) continue;
      handleLine(core, line, output);
    }
  });
}

function handleLine(core, line, output) {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    output.write(JSON.stringify({
      jsonrpc: "2.0", id: null,
      error: { code: -32700, message: "parse error" },
    }) + "\n");
    return;
  }
  if (message.id === undefined) return; // notification: nothing to answer
  try {
    const result = core.handle(message.method, message.params);
    output.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\n");
  } catch (error) {
    output.write(JSON.stringify({
      jsonrpc: "2.0", id: message.id,
      error: { code: error.jsonrpcCode || -32603, message: error.message.slice(0, 200) },
    }) + "\n");
  }
}

module.exports = { startStdioTransport };
