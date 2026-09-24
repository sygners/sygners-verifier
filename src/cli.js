#!/usr/bin/env node
// sygners-verify — verifies a .zip evidence file without sygners.
//
// One argument: the zip. Everything else comes from the `.env` (see
// `.env.example`). There are no options that change the result, on purpose: a
// verifier whose verdict depends on how you invoked it is no use for showing to
// anyone.
//
// Exit codes: 0 verifies · 1 does not verify (or mock) · 2 usage error.

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadEnv } from "./env.js";
import { options } from "./config.js";
import { verifyEvidence } from "./verify.js";
import { printReport } from "./report.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const HELP = `
sygners-verify <file.zip>

  Verifies a sygners evidence file against itself and against the chain it says
  it is anchored on. It never queries sygners.

  Configuration lives in the .env (RPC per chain, expected schema and attester,
  signer keys, OFFLINE). See .env.example.
`;

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] === "-h" || args[0] === "--help") {
    process.stdout.write(HELP);
    process.exit(args[0] === "-h" || args[0] === "--help" ? 0 : 2);
  }

  // The .env of the directory it runs in, otherwise the one next to the
  // verifier. Whatever is already in the environment wins.
  loadEnv([resolve(process.cwd(), ".env"), join(HERE, "..", ".env")]);

  const path = resolve(args[0]);
  if (!existsSync(path)) {
    process.stderr.write(`No such file: ${path}\n`);
    process.exit(2);
  }

  const r = await verifyEvidence(readFileSync(path), options());
  printReport(r, { file: path });
  process.exit(r.verdict === "VERIFIED" || r.verdict === "PARTIAL" ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`Unexpected verifier error: ${e?.stack ?? e}\n`);
  process.exit(2);
});
