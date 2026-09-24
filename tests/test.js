// The verifier's test suite. `node tests/test.js`.
//
// It runs end to end with no network and no sygners: the packages are built
// here and the chain is served by a fake JSON-RPC node (`fake-node.js`). What
// is being tested is not that the verifier says yes, but that it says NO when
// it should — which is the only thing that makes a verifier useful.

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync, strToU8 } from "fflate";
import { Wallet, keccak256 } from "ethers";
import { sha256Hex } from "../src/hash.js";
import { verifyEvidence } from "../src/verify.js";
import { options, SCHEMA_DEFINITION } from "../src/config.js";
import { STATEMENT, SIGNATURE_TYPES, canonicalDomain } from "../src/signature.js";
import { ZERO32, attestation, sygnersData, startNode } from "./fake-node.js";

const DIR = dirname(fileURLToPath(import.meta.url));
let failures = 0;
const check = (label, ok, extra = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "  ok  " : " FAIL "} ${label}${extra ? ` — ${extra}` : ""}`);
};
const has = (r, id, state) => r.checks.some((c) => c.id === id && c.state === state);

// ── The test package, built the way sygners builds one ───────────────────────
const CHAIN_ID = 11155111;
const EAS = "0xC2679fBD37d54388Ce493F1DB75320D236e1815e";
const SCHEMA_UID = `0x${"5c".repeat(32)}`;
const ATTESTER = "0x00000000000000000000000000000000000000AA";
const ISSUER = { email: "issuer@example.com", wallet: "0x0000000000000000000000000000000000000001" };
const SIGNER = { email: "signer@example.com", wallet: "0x0000000000000000000000000000000000000002" };
const REG_UID = `0x${"a1".repeat(32)}`;
const SIG_UID = `0x${"b2".repeat(32)}`;
const REG_TX = `0x${"c3".repeat(32)}`;
const SIG_TX = `0x${"d4".repeat(32)}`;
const DOC = strToU8("TEST CONTRACT\n" + "z".repeat(500));
const HASH = sha256Hex(DOC);
const SIGNED_AT = new Date("2026-09-01T12:30:00.000Z");

// The manifest's keys stay in Spanish: they are sygners' data.
function manifest(patch = {}) {
  return {
    formato: 1,
    documento: { id: "doc-1", titulo: "Test contract", nombreArchivo: "contract.txt", tipo: "text/plain", tamano: DOC.length, hash: HASH },
    cadena: { chainId: CHAIN_ID, registroUid: REG_UID, registroTxHash: REG_TX },
    emisor: ISSUER,
    firmantes: [
      { email: SIGNER.email, wallet: SIGNER.wallet, firmadoEl: SIGNED_AT.toISOString(), attestationUid: SIG_UID, txHash: SIG_TX, estado: "SIGNED" },
    ],
    fechas: { creado: "2026-09-01T12:00:00.000Z", ultimaFirma: SIGNED_AT.toISOString(), vence: "2026-09-08T12:30:00.000Z" },
    generadoEl: "2026-09-02T09:00:00.000Z",
    ...patch,
  };
}

function pack(m, document = DOC) {
  return zipSync(
    {
      "contract.txt": [document, { level: 0 }],
      "constancia.pdf": [strToU8("%PDF-1.7\n%%EOF\n"), { level: 0 }],
      "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
      // Spanish on purpose: it imitates the LEEME sygners writes.
      "LEEME.txt": [strToU8(`Calculá el SHA-256. Tiene que dar:\n  ${m.documento.hash}\n`), { level: 0 }],
    },
    { level: 0 },
  );
}

function chainState(patch = {}) {
  return {
    chainId: CHAIN_ID,
    attestations: {
      [REG_UID]: attestation({
        uid: REG_UID, schema: SCHEMA_UID, time: Math.floor(SIGNED_AT.getTime() / 1000) - 1800,
        recipient: ISSUER.wallet, attester: ATTESTER, refUID: ZERO32,
        data: sygnersData({ documentHash: HASH, action: "REGISTER", email: ISSUER.email, subject: ISSUER.wallet }),
      }),
      [SIG_UID]: attestation({
        uid: SIG_UID, schema: SCHEMA_UID, time: Math.floor(SIGNED_AT.getTime() / 1000) + 12,
        recipient: SIGNER.wallet, attester: ATTESTER, refUID: REG_UID,
        data: sygnersData({ documentHash: HASH, action: "SIGN", email: SIGNER.email, subject: SIGNER.wallet, sigHash: `0x${"ee".repeat(32)}` }),
      }),
      ...(patch.attestations ?? {}),
    },
    schemas: { [SCHEMA_UID]: SCHEMA_DEFINITION, ...(patch.schemas ?? {}) },
    receipts: { [REG_TX]: { to: EAS }, [SIG_TX]: { to: EAS }, ...(patch.receipts ?? {}) },
  };
}

// Configuration comes from the environment, just like in real life: the
// verifier no longer takes options as parameters.
function withEnv(vars, fn) {
  const previous = { ...process.env };
  for (const k of Object.keys(process.env)) {
    if (/^(RPC_URL|EAS_SCHEMA_UID|SYGNERS_ATTESTER|PK_SIGNER|OFFLINE)/.test(k)) delete process.env[k];
  }
  Object.assign(process.env, vars);
  return Promise.resolve(fn()).finally(() => {
    for (const k of Object.keys(process.env)) {
      if (/^(RPC_URL|EAS_SCHEMA_UID|SYGNERS_ATTESTER|PK_SIGNER|OFFLINE)/.test(k)) delete process.env[k];
    }
    Object.assign(process.env, previous);
  });
}

const offline = (zip) => withEnv({ OFFLINE: "true" }, () => verifyEvidence(zip, options()));

async function against(state, zip, extra = {}) {
  const node = await startNode(state);
  try {
    return await withEnv(
      // The wildcard as well as the specific one: that way the "the node is on
      // another chain" case also lands on the fake node and can be tested.
      { RPC_URL: node.url, [`RPC_URL_${state.chainId}`]: node.url, EAS_SCHEMA_UID: SCHEMA_UID, SYGNERS_ATTESTER: ATTESTER, ...extra },
      () => verifyEvidence(zip, options()),
    );
  } finally {
    await node.close();
  }
}

// ── 1. Offline, over the fixtures ────────────────────────────────────────────
console.log("\n--- offline ---");
{
  const read = (n) => readFileSync(join(DIR, "fixtures", n));
  const mock = await withEnv({}, () => verifyEvidence(read("mock.zip"), options()));
  check("a package from mock mode is flagged as MOCK", mock.verdict === "MOCK", mock.verdict);
  check("and the reason is the deterministic UID", has(mock, "chain.mock", "fail"));
  check("but the document does match its manifest", has(mock, "document.hash", "ok"));

  const tampered = await offline(read("tampered.zip"));
  check("a changed document does not verify", tampered.verdict === "FAILED", tampered.verdict);
  check("and the failure is the hash one", has(tampered, "document.hash", "fail"));

  const partial = await offline(read("fabricated.zip"));
  check("with no chain the verdict is PARTIAL and never VERIFIED", partial.verdict === "PARTIAL", partial.verdict);

  const broken = await offline(Buffer.from("this is not a zip"));
  check("a file that is not a zip does not break the program", broken.verdict === "FAILED" && has(broken, "zip", "fail"));
}

// ── 2. The happy path, against the fake node ─────────────────────────────────
console.log("\n--- against the chain (fake node) ---");
{
  const r = await against(chainState(), pack(manifest()));
  check("a package coherent with the chain VERIFIES", r.verdict === "VERIFIED",
        `${r.verdict}: ${r.checks.filter((c) => c.state === "fail").map((c) => c.id).join(", ")}`);
  check("the on-chain registration was confirmed", has(r, "registration.hash", "ok"));
  check("the signature references the registration", has(r, "signer.0.ref", "ok"));
  check("the schema was confirmed against the schema registry", has(r, "schema.definition", "ok"));
  check("the expected attester was confirmed", has(r, "registration.attester", "ok"));
  check("the transaction receipts were confirmed", has(r, "registration.tx", "ok") && has(r, "signer.0.tx", "ok"));
}

// ── 3. Every way of lying, one at a time ─────────────────────────────────────
console.log("\n--- negative cases ---");
const cases = [
  [
    "the anchored hash belongs to another document",
    chainState({ attestations: { [REG_UID]: attestation({ uid: REG_UID, schema: SCHEMA_UID, time: 1, attester: ATTESTER, recipient: ISSUER.wallet, data: sygnersData({ documentHash: `0x${"99".repeat(32)}`, action: "REGISTER", email: ISSUER.email, subject: ISSUER.wallet }) }) } }),
    pack(manifest()), {}, "registration.hash",
  ],
  [
    "the registration attestation was revoked",
    chainState({ attestations: { [REG_UID]: attestation({ uid: REG_UID, schema: SCHEMA_UID, time: 1, revocationTime: 1790000000, attester: ATTESTER, recipient: ISSUER.wallet, data: sygnersData({ documentHash: HASH, action: "REGISTER", email: ISSUER.email, subject: ISSUER.wallet }) }) } }),
    pack(manifest()), {}, "registration.exists",
  ],
  [
    "the signature was anchored by a wallet other than the manifest's",
    chainState({ attestations: { [SIG_UID]: attestation({ uid: SIG_UID, schema: SCHEMA_UID, time: 1, refUID: REG_UID, attester: ATTESTER, recipient: SIGNER.wallet, data: sygnersData({ documentHash: HASH, action: "SIGN", email: SIGNER.email, subject: "0x00000000000000000000000000000000000000ff", sigHash: `0x${"ee".repeat(32)}` }) }) } }),
    pack(manifest()), {}, "signer.0.wallet",
  ],
  [
    "the signature does not reference this document's registration",
    chainState({ attestations: { [SIG_UID]: attestation({ uid: SIG_UID, schema: SCHEMA_UID, time: 1, refUID: ZERO32, attester: ATTESTER, recipient: SIGNER.wallet, data: sygnersData({ documentHash: HASH, action: "SIGN", email: SIGNER.email, subject: SIGNER.wallet, sigHash: `0x${"ee".repeat(32)}` }) }) } }),
    pack(manifest()), {}, "signer.0.ref",
  ],
  [
    "it was anchored by an attester other than the expected one",
    chainState({ attestations: { [REG_UID]: attestation({ uid: REG_UID, schema: SCHEMA_UID, time: 1, attester: "0x00000000000000000000000000000000000000bb", recipient: ISSUER.wallet, data: sygnersData({ documentHash: HASH, action: "REGISTER", email: ISSUER.email, subject: ISSUER.wallet }) }) } }),
    pack(manifest()), {}, "registration.attester",
  ],
  [
    "the on-chain schema is not sygners'",
    chainState({ schemas: { [SCHEMA_UID]: "string anything" } }),
    pack(manifest()), {}, "schema.definition",
  ],
  [
    "the registration transaction does not exist",
    chainState({ receipts: { [REG_TX]: undefined } }),
    pack(manifest()), {}, "registration.tx",
  ],
  [
    "the manifest declares a signer who did not sign",
    chainState(),
    pack(manifest({ firmantes: [{ email: SIGNER.email, wallet: SIGNER.wallet, firmadoEl: null, attestationUid: SIG_UID, txHash: SIG_TX, estado: "PENDING" }] })),
    {}, "manifest.signers",
  ],
  [
    "the README says one hash and the manifest another",
    chainState(),
    (() => {
      const m = manifest();
      return zipSync({
        "contract.txt": [DOC, { level: 0 }],
        "constancia.pdf": [strToU8("%PDF-1.7\n%%EOF\n"), { level: 0 }],
        "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
        "LEEME.txt": [strToU8(`Tiene que dar:\n  0x${"00".repeat(32)}\n`), { level: 0 }],
      }, { level: 0 });
    })(),
    {}, "document.readme",
  ],
];

for (const [label, state, zip, extra, expectedId] of cases) {
  // `receipts: {hash: undefined}` leaves the key present; delete it so it is
  // really absent.
  for (const [k, v] of Object.entries(state.receipts)) if (v === undefined) delete state.receipts[k];
  const r = await against(state, zip, extra);
  check(`${label} → does not verify`, r.verdict === "FAILED", r.verdict);
  check(`   and it is reported in "${expectedId}"`, has(r, expectedId, "fail"),
        r.checks.filter((c) => c.state === "fail").map((c) => c.id).join(", "));
}

// ── 3b. The document named like one of the package's own files ───────────────
//
// A real case: a document called LEEME.txt. Whoever builds the zip writes both
// under the same entry, the fixed file wins, and the signed document is not in
// the package at all.
console.log("\n--- name collision ---");
{
  const m = manifest();
  m.documento.nombreArchivo = "LEEME.txt";
  const collided = zipSync(
    {
      "constancia.pdf": [strToU8("%PDF-1.7\n%%EOF\n"), { level: 0 }],
      "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
      // The document would have gone here and the package's own README
      // overwrote it.
      "LEEME.txt": [strToU8(`Tiene que dar:\n  ${m.documento.hash}\n`), { level: 0 }],
    },
    { level: 0 },
  );
  const r = await against(chainState(), collided);
  check("a document named like a package file does not verify", r.verdict === "FAILED", r.verdict);
  check("   and the report explains the collision",
        r.checks.find((c) => c.id === "package.document")?.detail?.includes("LEEME.txt"));
  check("   and the hash check says why there is nothing to hash",
        r.checks.find((c) => c.id === "document.hash")?.detail?.includes("took its place"));
  check("   while the on-chain anchoring still checks out", has(r, "registration.hash", "ok"));
}

// ── 4. Wrong network ─────────────────────────────────────────────────────────
console.log("\n--- wrong network ---");
{
  const r = await against({ ...chainState(), chainId: 1 }, pack(manifest()));
  check("a node on another chain aborts the cross-check", has(r, "chain.id", "fail") && r.verdict === "FAILED");
}

// ── 5. Format 2: the raw signature ───────────────────────────────────────────
//
// What changes: the package stops asking to be believed about who signed. The
// address is recovered from the signature, here, with no network.
console.log("\n--- format 2 (raw signature) ---");
{
  const w = Wallet.createRandom();
  const message = {
    documentId: "doc-1",
    documentHash: HASH,
    signerEmail: "signer@example.com",
    statement: STATEMENT,
    timestamp: Math.floor(SIGNED_AT.getTime() / 1000),
  };
  const signature = await w.signTypedData(canonicalDomain(CHAIN_ID), SIGNATURE_TYPES, message);
  const sigHash = keccak256(signature);

  const m2 = (patch = {}, signerPatch = {}) => ({
    ...manifest(),
    formato: 2,
    eip712: { dominio: canonicalDomain(CHAIN_ID), tipos: SIGNATURE_TYPES },
    firmantes: [
      {
        email: "signer@example.com", wallet: w.address, firmadoEl: SIGNED_AT.toISOString(),
        attestationUid: SIG_UID, txHash: SIG_TX, estado: "SIGNED",
        mensaje: message, firma: signature, sigHash, ...signerPatch,
      },
    ],
    ...patch,
  });

  const chain2 = (sh = sigHash, subject = w.address) => chainState({
    attestations: {
      [SIG_UID]: attestation({
        uid: SIG_UID, schema: SCHEMA_UID, time: Math.floor(SIGNED_AT.getTime() / 1000) + 12,
        recipient: subject, attester: ATTESTER, refUID: REG_UID,
        data: sygnersData({ documentHash: HASH, action: "SIGN", email: "signer@example.com", subject, sigHash: sh }),
      }),
    },
  });

  const r = await against(chain2(), pack(m2()));
  check("a coherent format 2 package VERIFIES", r.verdict === "VERIFIED",
        `${r.verdict}: ${r.checks.filter((x) => x.state === "fail").map((x) => x.id).join(", ")}`);
  check("the address was recovered from the signature", has(r, "signer.0.recovered", "ok"));
  check("the package's EIP-712 domain is sygners'", has(r, "signature.eip712", "ok"));
  check("the package's signature is the one anchored on chain", has(r, "signer.0.sighash", "ok"));

  const off = await offline(pack(m2()));
  check("with no chain, the signature is verified anyway", has(off, "signer.0.recovered", "ok") && off.verdict === "PARTIAL", off.verdict);

  const other = Wallet.createRandom();
  const foreignSig = await other.signTypedData(canonicalDomain(CHAIN_ID), SIGNATURE_TYPES, message);
  const rForeign = await against(chain2(keccak256(foreignSig), w.address), pack(m2({}, { firma: foreignSig, sigHash: keccak256(foreignSig) })));
  check("a signature from another wallet does not verify", rForeign.verdict === "FAILED" && has(rForeign, "signer.0.recovered", "fail"));

  const foreignMsg = { ...message, documentHash: `0x${"77".repeat(32)}` };
  const otherDocSig = await w.signTypedData(canonicalDomain(CHAIN_ID), SIGNATURE_TYPES, foreignMsg);
  const rOther = await against(chain2(keccak256(otherDocSig)), pack(m2({}, { mensaje: foreignMsg, firma: otherDocSig, sigHash: keccak256(otherDocSig) })));
  check("a valid signature over ANOTHER document does not verify", rOther.verdict === "FAILED" && has(rOther, "signer.0.message.hash", "fail"));

  const otherNetSig = await w.signTypedData(canonicalDomain(1), SIGNATURE_TYPES, message);
  const rDomain = await against(
    chain2(keccak256(otherNetSig)),
    pack(m2({ eip712: { dominio: canonicalDomain(1), tipos: SIGNATURE_TYPES } }, { firma: otherNetSig, sigHash: keccak256(otherNetSig) })),
  );
  check("a tailored EIP-712 domain does not get through", rDomain.verdict === "FAILED" && has(rDomain, "signature.eip712", "fail"));
  check("   and recovery runs anyway with the canonical domain", has(rDomain, "signer.0.recovered", "fail"));

  const rSig = await against(chain2(`0x${"aa".repeat(32)}`), pack(m2()));
  check("if the anchored fingerprint is another, it does not verify", rSig.verdict === "FAILED" && has(rSig, "signer.0.sighash", "fail"));

  const otherTextMsg = { ...message, statement: "I accept anything." };
  const otherTextSig = await w.signTypedData(canonicalDomain(CHAIN_ID), SIGNATURE_TYPES, otherTextMsg);
  const rText = await against(chain2(keccak256(otherTextSig)), pack(m2({}, { mensaje: otherTextMsg, firma: otherTextSig, sigHash: keccak256(otherTextSig) })));
  check("a different statement does not verify", rText.verdict === "FAILED" && has(rText, "signer.0.message.statement", "fail"));

  const rOld = await against(chain2(`0x${"ee".repeat(32)}`), pack(m2({}, { mensaje: null, firma: null, sigHash: null })));
  check("a signer with no raw signature warns but does not invalidate", has(rOld, "signer.0.raw", "warn") && rOld.verdict === "VERIFIED", rOld.verdict);

  const r1 = await against(chainState(), pack(manifest()));
  check("a format 1 manifest skips the raw-signature block", has(r1, "signature.raw", "skipped") && r1.verdict === "VERIFIED");
}

// ── 6. The private keys provided ─────────────────────────────────────────────
//
// What is tested here is not the cryptography —deriving an address— but the
// policy: what counts as confirmation, what as a warning and what fails. And
// that the key never shows up anywhere in the output.
console.log("\n--- provided keys ---");
{
  const w = Wallet.createRandom();
  const message = {
    documentId: "doc-1", documentHash: HASH, signerEmail: "signer@example.com",
    statement: STATEMENT, timestamp: Math.floor(SIGNED_AT.getTime() / 1000),
  };
  const signature = await w.signTypedData(canonicalDomain(CHAIN_ID), SIGNATURE_TYPES, message);
  const sigHash = keccak256(signature);
  const zip = pack({
    ...manifest(), formato: 2,
    eip712: { dominio: canonicalDomain(CHAIN_ID), tipos: SIGNATURE_TYPES },
    firmantes: [{
      email: "signer@example.com", wallet: w.address, firmadoEl: SIGNED_AT.toISOString(),
      attestationUid: SIG_UID, txHash: SIG_TX, estado: "SIGNED", mensaje: message, firma: signature, sigHash,
    }],
  });
  const chainWithSignature = chainState({
    attestations: {
      [SIG_UID]: attestation({
        uid: SIG_UID, schema: SCHEMA_UID, time: Math.floor(SIGNED_AT.getTime() / 1000) + 12,
        recipient: w.address, attester: ATTESTER, refUID: REG_UID,
        data: sygnersData({ documentHash: HASH, action: "SIGN", email: "signer@example.com", subject: w.address, sigHash }),
      }),
    },
  });
  const withKeys = (vars, z = zip, state = chainWithSignature) => against(state, z, vars);

  const r = await withKeys({ PK_SIGNER1: w.privateKey });
  check("the signer's key confirms them", r.verdict === "VERIFIED" && has(r, "key.PK_SIGNER1", "ok"), r.verdict);
  check("and the key shows up nowhere in the output",
        !JSON.stringify(r).toLowerCase().includes(w.privateKey.slice(2).toLowerCase()));

  const noPrefix = await withKeys({ PK_SIGNER1: w.privateKey.slice(2) });
  check("a key without the leading 0x is accepted too", has(noPrefix, "key.PK_SIGNER1", "ok"));

  const foreign = await withKeys({ PK_SIGNER1: Wallet.createRandom().privateKey });
  check("a key belonging to nobody in the package does not verify",
        foreign.verdict === "FAILED" && has(foreign, "keys.no-match", "fail"));

  const mixed = await withKeys({ PK_SIGNER1: w.privateKey, PK_SIGNER2: Wallet.createRandom().privateKey });
  check("with one that matches and one that does not, the latter warns and does not invalidate",
        mixed.verdict === "VERIFIED" && has(mixed, "key.PK_SIGNER2", "warn"), mixed.verdict);

  const broken = await withKeys({ PK_SIGNER1: w.privateKey, PK_SIGNER2: "not-a-key" });
  check("a variable with garbage in it fails", has(broken, "key.PK_SIGNER2", "fail"));
  check("   and it does not print what was put there", !JSON.stringify(broken).includes("not-a-key"));

  const freeName = await withKeys({ PK_SIGNER_ANA: w.privateKey });
  check("the variable suffix is free (PK_SIGNER_ANA)", has(freeName, "key.PK_SIGNER_ANA", "ok"));

  const noKeys = await withKeys({});
  check("with no keys provided, the report warns about it",
        has(noKeys, "keys.none-provided", "warn") && noKeys.verdict === "VERIFIED", noKeys.verdict);
  check("   and the warning names the unconfirmed signers",
        noKeys.checks.find((x) => x.id === "keys.none-provided")?.detail.includes("signer@example.com"));
}

console.log(`\n${failures === 0 ? "all green" : `${failures} FAILURES`}\n`);
process.exit(failures === 0 ? 0 : 1);
