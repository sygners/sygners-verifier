// The report: structured text, meant to be read end to end and to be pasted
// elsewhere without losing anything.
//
// It is organized by SUBJECT rather than by kind of check: the package, the
// document, the anchoring, and then one block per signer with absolutely
// everything about them together —what the manifest says, what their signature
// proves and what the chain says. The earlier version grouped by where each
// check had been made, which is how the verifier produces them and not how
// someone deciding whether a signature holds needs to read them.
//
// Every check line carries its state and, below it, the value it was resolved
// with: whoever reads has to be able to redo the arithmetic, not trust the
// verdict.

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (COLOR ? `\u001b[${code}m${s}\u001b[0m` : s);
const green = (s) => c("32", s);
const red = (s) => c("31", s);
const yellow = (s) => c("33", s);
const grey = (s) => c("90", s);
const bold = (s) => c("1", s);

const MARK = {
  ok: green("[ ok ]"),
  fail: red("[FAIL ]"),
  warn: yellow("[warn ]"),
  skipped: grey("[  -  ]"),
  info: grey("[  ·  ]"),
};

const VERDICT = {
  VERIFIED: {
    text: "VERIFIED",
    paint: green,
    gloss:
      "The package's document is the one that was anchored, and the attestations are on chain and say what the manifest says they say.",
  },
  PARTIAL: {
    text: "PARTIALLY VERIFIED (no chain)",
    paint: yellow,
    gloss:
      "The package is internally consistent: the document matches the manifest's hash. It was NOT cross-checked against the chain, so this does not yet prove when it existed or who anchored it.",
    glossWithSignatures:
      "The signatures were verified: the address recovered from each one is the one the manifest declares, and the document matches the signed hash. The only thing missing is the chain, which is what dates the anchoring and says who did it.",
  },
  MOCK: {
    text: "MOCK EVIDENCE",
    paint: red,
    gloss:
      "The package came from a sygners instance with NO chain configured: its on-chain identifiers are deterministic and correspond to no attestation. It proves nothing to a third party.",
  },
  FAILED: {
    text: "DOES NOT VERIFY",
    paint: red,
    gloss: "At least one blocking check failed.",
  },
};

const WIDTH = 74;
const RULE = "─".repeat(WIDTH);
const DOUBLE_RULE = "═".repeat(WIDTH);

// Which subject each check belongs to. The id rules: `signer.3.whatever` is the
// fourth signer's, no matter whether the check was made against their signature
// or against the chain.
function split(checks) {
  const s = { package: [], document: [], anchoring: [], scheme: [], keys: [], signers: new Map() };
  for (const ch of checks) {
    const perSigner = /^signer\.(\d+)\./.exec(ch.id);
    if (perSigner) {
      const i = Number(perSigner[1]);
      if (!s.signers.has(i)) s.signers.set(i, []);
      s.signers.get(i).push(ch);
      continue;
    }
    if (ch.area === "keys") s.keys.push(ch);
    else if (ch.id.startsWith("signature.")) s.scheme.push(ch);
    else if (ch.area === "document") s.document.push(ch);
    else if (ch.area === "chain" || ch.id.startsWith("registration.") || ch.id.startsWith("schema."))
      s.anchoring.push(ch);
    else s.package.push(ch);
  }
  return s;
}

export function printReport(r, { file }) {
  const L = [];
  const op = r.operation;
  const sec = split(r.checks);

  const field = (k, v) => {
    if (v === null || v === undefined || v === "") return;
    L.push(` ${k.padEnd(16)}${v}`);
  };
  const heading = (text) => {
    L.push("");
    L.push(grey(RULE));
    L.push(` ${bold(text)}`);
    L.push(grey(RULE));
  };
  // One check: its state, its claim and the value it was resolved with.
  const line = (ch, stripPrefix) => {
    let t = ch.title;
    if (stripPrefix && t.startsWith(`${stripPrefix}: `)) t = t.slice(stripPrefix.length + 2);
    L.push(` ${MARK[ch.state]} ${t}`);
    if (ch.detail) {
      for (const part of wrap(ch.detail, WIDTH - 10)) L.push(`        ${grey(part)}`);
    }
  };
  const block = (checks, stripPrefix) => {
    if (checks.length === 0) return;
    L.push("");
    for (const ch of checks) line(ch, stripPrefix);
  };

  // ── Header ──
  const v = VERDICT[r.verdict];
  const signaturesProven = r.checks.some(
    (x) => /^signer\.\d+\.recovered$/.test(x.id) && x.state === "ok",
  );
  const gloss = (signaturesProven && v.glossWithSignatures) || v.gloss;

  L.push("");
  L.push(grey(DOUBLE_RULE));
  L.push(` ${bold("EVIDENCE FILE VERIFICATION")} ${grey("· sygners · without the platform")}`);
  L.push(grey(DOUBLE_RULE));
  field("File", file);
  field("Verified at", new Date().toISOString());
  field("Verdict", v.paint(bold(v.text)));
  for (const part of wrap(gloss, WIDTH - 17)) L.push(` ${"".padEnd(16)}${grey(part)}`);
  field(
    "Checks",
    `${r.summary.ok} ok · ${r.summary.fails} failed · ${r.summary.warns} warnings · ${r.summary.skipped} skipped`,
  );

  // ── 1. Package ──
  heading("1. PACKAGE");
  field("Format", op ? `manifest format ${op.format ?? "?"}` : null);
  field("Generated", op?.generatedAt);
  block(sec.package);

  // ── 2. Document ──
  heading("2. DOCUMENT");
  field("Operation", op?.title);
  field("Id", op?.documentId);
  field("File", op?.file);
  field("Size", op?.size != null ? `${op.size} bytes` : null);
  field("SHA-256", op?.computedHash ?? op?.declaredHash);
  field("Issuer", op?.issuer ? `${op.issuer.email} · ${op.issuer.wallet}` : null);
  field("Created", op?.dates?.creado);
  field("Last signature", op?.dates?.ultimaFirma);
  field("Copy expires", op?.dates?.vence);
  block(sec.document);

  // ── 3. Anchoring ──
  heading("3. ANCHORING ON CHAIN");
  field("Network", op?.chainId ? `${op.network} (chainId ${op.chainId})` : null);
  field("Registration", op?.registrationUid);
  field("Explorer", op?.registrationUrl);
  field("Attester", op?.attester);
  field("Schema", op?.schemaUid);
  block(sec.anchoring);

  // ── 4. Signing scheme ──
  if (sec.scheme.length) {
    heading("4. SIGNING SCHEME (EIP-712)");
    block(sec.scheme);
  }
  let n = sec.scheme.length ? 5 : 4;

  // ── 5+. One block per signer ──
  const signers = op?.signers ?? [];
  const total = signers.length;
  for (const [i, f] of signers.entries()) {
    heading(`${n++}. SIGNER ${i + 1} OF ${total} — ${f.email ?? "(no email)"}`);
    field("Wallet", f.wallet);
    field("State", f.state);
    field("Signed at", f.signedAt);
    field("Attestation", f.attestationUid);
    field("Explorer", f.url);
    field("Transaction", f.txHash);
    field("Fingerprint", f.sigHash);
    field(
      "Raw signature",
      f.signature ? `${f.signature.slice(0, 20)}… (${(f.signature.length - 2) / 2} bytes)` : grey("not included in the package"),
    );
    block(sec.signers.get(i) ?? [], f.email);
  }
  // Checks for signers the manifest never listed.
  for (const [i, checks] of sec.signers) {
    if (i < total) continue;
    heading(`${n++}. SIGNER ${i + 1}`);
    block(checks);
  }

  // ── Keys ──
  if (sec.keys.length) {
    const provided = sec.keys.some((x) => x.id.startsWith("key."));
    heading(`${n++}. SIGNERS' PRIVATE KEYS`);
    if (provided) L.push(grey(" They establish control of the wallet, not identity."));
    block(sec.keys);
  }

  // ── Result ──
  heading("RESULT");
  L.push(` ${v.paint(bold(v.text))}`);
  const fails = r.checks.filter((x) => x.state === "fail");
  const warns = r.checks.filter((x) => x.state === "warn");
  if (fails.length) {
    L.push("");
    L.push(` ${red(bold(`Failures (${fails.length})`))}`);
    for (const f of fails) {
      L.push(` ${red("·")} ${f.title}`);
      if (f.detail) for (const p of wrap(f.detail, WIDTH - 4)) L.push(`   ${grey(p)}`);
    }
  }
  if (warns.length) {
    L.push("");
    L.push(` ${yellow(bold(`Warnings (${warns.length})`))}`);
    for (const w of warns) L.push(` ${yellow("·")} ${w.title}`);
  }
  L.push("");
  process.stdout.write(L.join("\n") + "\n");
}

// Wraps text to at most `width` columns, without breaking words.
function wrap(text, width) {
  const out = [];
  for (const paragraph of String(text).split("\n")) {
    let line = "";
    for (const word of paragraph.split(/\s+/)) {
      if (line && (line + " " + word).length > width) {
        out.push(line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    out.push(line);
  }
  return out;
}
