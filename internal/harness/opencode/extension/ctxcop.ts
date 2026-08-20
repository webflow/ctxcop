// ctxcop bridge for opencode. Bun loads and transpiles .ts natively.
// Spawns `ctxcop hook opencode <subcmd>` per event. Fail-open everywhere.

import type { Plugin } from "@opencode-ai/plugin";
import { spawn } from "node:child_process";

const CTXCOP_BIN = process.env.CTXCOP_BIN ?? "ctxcop";

async function callCtxcop(subcmd: string, payload: unknown): Promise<any> {
  return new Promise((resolve) => {
    let proc;
    try {
      proc = spawn(CTXCOP_BIN, ["hook", "opencode", subcmd], { stdio: ["pipe", "pipe", "inherit"] });
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

// Replace every own enumerable key of `dst` with the keys of `src`,
// preserving the object identity that opencode's tool runner already
// captured a reference to.
function replaceInPlace(dst: Record<string, any>, src: Record<string, any>) {
  for (const k of Object.keys(dst)) delete dst[k];
  Object.assign(dst, src);
}

export const ctxcop: { id: string; server: Plugin } = {
  id: "ctxcop",
  server: async (_input) => ({
    "tool.execute.before": async (input, output) => {
      const r = await callCtxcop("tool-execute-before", {
        tool: input.tool,
        sessionID: input.sessionID,
        callID: input.callID,
        args: output.args,
      });
      if (r?.block) {
        throw new Error(r.reason ?? "ctxcop: blocked tool call (credential-shape data in input).");
      }
      if (r?.args && typeof r.args === "object") {
        replaceInPlace(output.args, r.args);
      }
    },

    "tool.execute.after": async (input, output) => {
      const r = await callCtxcop("tool-execute-after", {
        tool: input.tool,
        sessionID: input.sessionID,
        callID: input.callID,
        args: input.args,
        output: output.output,
      });
      if (typeof r?.output === "string") {
        output.output = r.output;
      }
    },
  }),
};
