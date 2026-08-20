// ctxcop bridge for pi.dev. Pi transpiles this via jiti at load.
// Spawns `ctxcop hook pi <subcmd>` per event. Fail-open everywhere.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";

const CTXCOP_BIN = process.env.CTXCOP_BIN ?? "ctxcop";

async function callCtxcop(subcmd: string, payload: unknown): Promise<unknown> {
  return new Promise((resolve) => {
    let proc;
    try {
      proc = spawn(CTXCOP_BIN, ["hook", "pi", subcmd], { stdio: ["pipe", "pipe", "inherit"] });
    } catch {
      resolve({});
      return;
    }
    let out = "";
    proc.stdout?.on("data", (d) => (out += d));
    proc.on("error", () => resolve({}));
    proc.on("close", () => {
      try { resolve(out ? JSON.parse(out) : {}); }
      catch { resolve({}); }
    });
    try {
      proc.stdin?.write(JSON.stringify(payload));
      proc.stdin?.end();
    } catch {
      resolve({});
    }
  });
}

export default function (pi: ExtensionAPI) {
  let primed = false;

  pi.on("session_start", (_event, ctx) => {
    if (ctx.hasUI) {
      ctx.ui.notify("ctxcop is active — LLM payloads will be scanned for credentials before send.", "info");
    }
  });

  pi.on("before_agent_start", async (event) => {
    if (primed) return undefined;
    primed = true;
    const r = (await callCtxcop("before-agent-start", event)) as { systemPrompt?: string };
    return r.systemPrompt ? { systemPrompt: r.systemPrompt } : undefined;
  });

  pi.on("tool_call", async (event) => {
    const e = event as { toolName: string };
    if (!e.toolName?.startsWith("mcp__")) return undefined;
    const r = (await callCtxcop("tool-call", event)) as { block?: boolean; reason?: string };
    if (r.block) return { block: true, reason: r.reason ?? "ctxcop: credential detected in MCP tool input." };
    return undefined;
  });

  pi.on("before_provider_request", async (event) => {
    const r = (await callCtxcop("before-provider-request", event)) as { payload?: unknown };
    return r.payload ?? undefined;
  });
}
