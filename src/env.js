// Reading the `.env`, with no dependencies.
//
// On purpose: this verifier has to run ten years from now against a zip someone
// found in a drawer, and every package it adds is a package that may not
// install by then. `dotenv` would do exactly this and nothing more.
//
// Precedence: whatever is already in `process.env` always wins — so a variable
// passed on the command line (`RPC_URL=... node src/cli.js ...`) overrides the
// file without editing it.

import { readFileSync, existsSync } from "node:fs";

function parse(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const cut = line.indexOf("=");
    if (cut === -1) continue;
    const key = line.slice(0, cut).trim().replace(/^export\s+/, "");
    let value = line.slice(cut + 1).trim();
    // A trailing comment, but only if the value is not quoted: a URL with a `#`
    // in it is odd but legal.
    if (!/^["']/.test(value)) value = value.replace(/\s+#.*$/, "").trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }
  return out;
}

// Loads the first file that exists in the list, without overriding what is
// already defined in the environment. Returns the path used, or null.
export function loadEnv(paths) {
  for (const path of paths) {
    if (!path || !existsSync(path)) continue;
    const values = parse(readFileSync(path, "utf8"));
    for (const [k, v] of Object.entries(values)) {
      if (process.env[k] === undefined || process.env[k] === "") process.env[k] = v;
    }
    return path;
  }
  return null;
}

// One variable, normalized: empty is the same as absent.
export function env(name) {
  const v = process.env[name];
  return v && v.trim() !== "" ? v.trim() : undefined;
}

export function envBool(name, fallback = false) {
  const v = env(name);
  if (v === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(v);
}
