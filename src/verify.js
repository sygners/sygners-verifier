// The verifier: takes the bytes of a .zip and returns a list of checks and a
// verdict.
//
// Three design rules, all three deliberate:
//
//  1. **Nothing throws over a finding.** A broken zip, a manifest without
//     fields or a non-existent attestation are RESULTS, and the report shows
//     them next to everything else. Only a program error interrupts.
//  2. **Everything that can run, runs.** A failing hash does not cancel the
//     chain checks: whoever verifies wants the whole picture, not the first
//     problem.
//  3. **Nothing is asked of sygners.** The only sources are the zip and an RPC
//     node of the chain the manifest itself declares.
//
// ⚠️ The manifest's field names are in Spanish (`documento`, `firmantes`,
// `cadena`…) because they are DATA: they are the keys sygners writes into the
// JSON. Renaming them here would simply stop reading the file.

import { sha256Hex, hashesEqual } from "./hash.js";
import {
  STATEMENT,
  compareEip712,
  isWellFormedSignature,
  fingerprint,
  sameAddress,
  recoverSigner,
} from "./signature.js";
import { openEvidence, CERTIFICATE_NAME, README_NAME, MANIFEST_NAME } from "./zip.js";
import { detectMock } from "./mock.js";
import { providedKeys } from "./keys.js";
import {
  ACTION_SIGN,
  ACTION_REGISTER,
  ZERO_BYTES32,
  RPC_TIMEOUT_MS,
  SCHEMA_DEFINITION,
  TOLERANCE_SECONDS,
  chainFor,
  expectations,
} from "./config.js";
import {
  nodeChainId,
  decodeData,
  addr,
  readAttestation,
  readReceipt,
  readSchema,
  provider,
} from "./eas.js";

// Format 1: the original. Format 2 (2026-09-22): adds `eip712` and, per signer,
// `mensaje` + `firma` + `sigHash` — the raw signature, which is what allows
// recovering the address without trusting anyone.
const MAX_FORMAT = 2;
const FORMAT_WITH_RAW_SIGNATURE = 2;

class Checks {
  constructor() {
    this.list = [];
  }
  add(area, id, title, state, detail, extra = {}) {
    this.list.push({ area, id, title, state, detail: detail ?? null, ...extra });
    return state;
  }
  ok(area, id, title, detail, extra) {
    return this.add(area, id, title, "ok", detail, extra);
  }
  fail(area, id, title, detail, extra) {
    return this.add(area, id, title, "fail", detail, extra);
  }
  warn(area, id, title, detail, extra) {
    return this.add(area, id, title, "warn", detail, extra);
  }
  skip(area, id, title, detail, extra) {
    return this.add(area, id, title, "skipped", detail, extra);
  }
  info(area, id, title, detail, extra) {
    return this.add(area, id, title, "info", detail, extra);
  }
  // `condition ? ok : fail`, which is the shape of almost every check.
  when(cond, area, id, title, okDetail, failDetail, extra) {
    return cond
      ? this.ok(area, id, title, okDetail, extra)
      : this.fail(area, id, title, failDetail, extra);
  }
  count(state) {
    return this.list.filter((c) => c.state === state).length;
  }
}

const isHex32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
const date = (v) => {
  if (typeof v !== "string") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};
const secs = (d) => Math.floor(d.getTime() / 1000);

// ── 1. Package structure ─────────────────────────────────────────────────────
function checkStructure(c, zip) {
  const missing = [MANIFEST_NAME, CERTIFICATE_NAME, README_NAME].filter(
    (n) => !zip.files.includes(n),
  );
  c.when(
    missing.length === 0,
    "package",
    "package.parts",
    "The package carries the pieces the format declares",
    `${zip.files.length} entries: ${zip.files.join(", ")}`,
    `Missing: ${missing.join(", ")}`,
  );

  if (zip.documentCandidates.length === 1) {
    c.ok("package", "package.document", "There is exactly one document inside", zip.documentName);
  } else if (zip.documentCandidates.length === 0) {
    c.fail("package", "package.document", "There is exactly one document inside", "There is none.");
  } else {
    c.fail(
      "package",
      "package.document",
      "There is exactly one document inside",
      `There are ${zip.documentCandidates.length}: ${zip.documentCandidates.join(", ")}. There is no way to tell which one was signed.`,
    );
  }

  if (zip.pdf) {
    const header = Buffer.from(zip.pdf.slice(0, 5)).toString("latin1");
    c.when(
      header.startsWith("%PDF"),
      "package",
      "package.certificate",
      "The certificate is a PDF",
      `${zip.pdf.length} bytes`,
      `It starts with ${JSON.stringify(header)}, not with %PDF.`,
    );
  }
}

// ── 2. Manifest shape ────────────────────────────────────────────────────────
function checkManifest(c, m) {
  const missing = [];
  const require_ = (path) => {
    const v = path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), m);
    if (v === undefined || v === null || v === "") missing.push(path);
    return v;
  };
  for (const path of [
    "formato",
    "documento.id",
    "documento.titulo",
    "documento.nombreArchivo",
    "documento.hash",
    "cadena.chainId",
    "emisor.email",
    "emisor.wallet",
    "fechas.creado",
    "generadoEl",
  ]) {
    require_(path);
  }
  if (!Array.isArray(m.firmantes)) missing.push("firmantes");

  c.when(
    missing.length === 0,
    "manifest",
    "manifest.fields",
    "The manifest has every required field",
    null,
    `Missing: ${missing.join(", ")}`,
  );

  if (m.formato >= 1 && m.formato <= MAX_FORMAT) {
    c.ok(
      "manifest",
      "manifest.format",
      "Known manifest format",
      m.formato >= FORMAT_WITH_RAW_SIGNATURE
        ? `format ${m.formato} — carries each signer's raw signature`
        : `format ${m.formato} — no raw signature (predates 2026-09-22)`,
    );
  } else if (typeof m.formato === "number" && m.formato > MAX_FORMAT) {
    c.warn(
      "manifest",
      "manifest.format",
      "Known manifest format",
      `The manifest declares format ${m.formato} and this verifier understands up to ${MAX_FORMAT}. The checks run anyway, but there may be new fields it does not look at.`,
    );
  } else {
    c.fail(
      "manifest",
      "manifest.format",
      "Known manifest format",
      `Format ${JSON.stringify(m.formato)}, unexpected.`,
    );
  }

  c.when(
    isHex32(m?.documento?.hash),
    "manifest",
    "manifest.hash",
    "The declared hash looks like a SHA-256",
    m?.documento?.hash,
    `${JSON.stringify(m?.documento?.hash)} is not 0x + 64 hex.`,
  );

  const w = addr(m?.emisor?.wallet);
  c.when(
    Boolean(w),
    "manifest",
    "manifest.issuer",
    "The issuer's wallet is a valid address",
    `${m?.emisor?.email} — ${w}`,
    `${JSON.stringify(m?.emisor?.wallet)} is not an address.`,
  );

  // Dates: created ≤ last signature ≤ generated. A manifest claiming it was
  // generated before the signature it describes contradicts itself.
  const created = date(m?.fechas?.creado);
  const last = date(m?.fechas?.ultimaFirma);
  const generated = date(m?.generadoEl);
  const coherent =
    created &&
    generated &&
    (!last || (last >= created && last <= generated)) &&
    created <= generated;
  c.when(
    Boolean(coherent),
    "manifest",
    "manifest.dates",
    "The manifest's dates are coherent with each other",
    `created ${m?.fechas?.creado}${last ? ` · last signature ${m.fechas.ultimaFirma}` : ""} · generated ${m?.generadoEl}`,
    "Creation, last signature and generation are not in order.",
  );

  const signers = Array.isArray(m.firmantes) ? m.firmantes : [];
  const unsigned = signers.filter((f) => f.estado !== "SIGNED");
  if (signers.length === 0) {
    c.fail("manifest", "manifest.signers", "There is at least one signer", "The list is empty.");
  } else if (unsigned.length > 0) {
    // The server only builds the manifest once the document is COMPLETED, so
    // this should never happen: if it does, this is not the manifest sygners
    // produces.
    c.fail(
      "manifest",
      "manifest.signers",
      "Every signer is listed as signed",
      `${unsigned.length} of ${signers.length} are not SIGNED: ${unsigned
        .map((f) => `${f.email} (${f.estado})`)
        .join(", ")}`,
    );
  } else {
    c.ok(
      "manifest",
      "manifest.signers",
      "Every signer is listed as signed",
      `${signers.length} signer(s)`,
    );
  }
}

// ── 3. The document against what the manifest declares ───────────────────────
function checkDocument(c, zip, m) {
  if (!zip.document) {
    c.fail("document", "document.hash", "The document is the one that was anchored", "There is no document to hash.");
    return null;
  }
  const computed = sha256Hex(zip.document);
  const declared = m?.documento?.hash;

  // THE check. Everything else describes; this one proves.
  c.when(
    hashesEqual(computed, declared),
    "document",
    "document.hash",
    "The document's SHA-256 is the one the manifest declares",
    computed,
    `Computed ${computed}, declared ${declared}. The file inside is NOT the one that was signed.`,
    { expected: declared ?? null, got: computed },
  );

  const size = m?.documento?.tamano;
  if (typeof size === "number") {
    c.when(
      size === zip.document.length,
      "document",
      "document.size",
      "The size matches the declared one",
      `${zip.document.length} bytes`,
      `The manifest says ${size} bytes and the file has ${zip.document.length}.`,
    );
  }

  const name = m?.documento?.nombreArchivo;
  if (name) {
    c[name === zip.documentName ? "ok" : "warn"](
      "document",
      "document.name",
      "The file name matches the declared one",
      name === zip.documentName
        ? name
        : `The zip carries it as "${zip.documentName}" and the manifest calls it "${name}". The name is not part of what was anchored; what proves the file's identity is the hash.`,
    );
  }

  // LEEME.txt repeats the hash in prose. A mismatch with the manifest means
  // somebody edited one of the two pieces.
  if (zip.readme && isHex32(declared)) {
    const inReadme = zip.readme.includes(declared);
    c[inReadme ? "ok" : "fail"](
      "document",
      "document.readme",
      "The README repeats the same hash as the manifest",
      inReadme ? null : "The hash written in LEEME.txt is not the manifest's: somebody touched one of the two pieces.",
    );
  }

  return computed;
}

// ── 3.5 The EIP-712 signatures, with no network ──────────────────────────────
//
// This block is what changed what a package proves on its own. It queries
// nothing: it recovers the address from the raw signature and compares it with
// the declared one. If it matches, that wallet signed that message, and you do
// not have to trust the chain or sygners to know it.
function checkRawSignatures(c, m) {
  const signers = Array.isArray(m.firmantes) ? m.firmantes : [];
  const chainId = Number(m?.cadena?.chainId);

  if (!(m.formato >= FORMAT_WITH_RAW_SIGNATURE)) {
    c.skip(
      "signatures",
      "signature.raw",
      "Recovering the address from the signature",
      `The manifest is format ${m.formato}, older than the package carrying raw signatures. What was anchored on chain is the fingerprint (keccak256 of the signature), not the signature, so there is nothing here to recover from.`,
    );
    return;
  }

  // The package's domain is verified, not used blindly: a tailored one would
  // make a signature produced elsewhere recover cleanly here.
  const cmp = compareEip712(m.eip712, chainId);
  c.when(
    cmp.ok,
    "signatures",
    "signature.eip712",
    "The package's EIP-712 domain and types are sygners'",
    `sygners · v1 · chainId ${chainId}`,
    `The package declares a different signing scheme: ${cmp.problems.join("; ")}. Recovery runs anyway with the canonical domain.`,
  );

  // The issuer's wallet does not sign: it identifies the on-chain registration.
  // When the issuer also signs, they appear twice with different addresses, and
  // that confuses enough people to be worth spelling out.
  const issuerAlsoSigns = signers.some(
    (f) => String(f.email).toLowerCase() === String(m?.emisor?.email ?? "").toLowerCase(),
  );
  if (issuerAlsoSigns) {
    c.info(
      "signatures",
      "signature.issuer",
      "The issuer also signs",
      `The issuer's wallet (${m?.emisor?.wallet}) is the REGISTRATION's and signs nothing, so it is not recovered from any signature. The ones verified are firmantes[].wallet: that they differ is expected.`,
    );
  }

  for (const [i, f] of signers.entries()) {
    const who = f.email ?? `signer ${i + 1}`;

    if (f.firma === null || f.firma === undefined) {
      c.warn(
        "signatures",
        `signer.${i}.raw`,
        `${who}: the package carries their raw signature`,
        "It does not. This is a signature older than format 2 (or a signer who never signed): their evidence is still the on-chain attestation, but the address cannot be recovered here.",
      );
      continue;
    }
    if (!isWellFormedSignature(f.firma)) {
      c.fail("signatures", `signer.${i}.raw`, `${who}: their signature looks like a signature`, `${JSON.stringify(f.firma)} is not 65 bytes of hex.`);
      continue;
    }
    if (!f.mensaje || typeof f.mensaje !== "object") {
      c.fail(
        "signatures",
        `signer.${i}.message`,
        `${who}: the package carries the message they signed`,
        "The signature is there but the message is not: there is nothing to verify it against.",
      );
      continue;
    }

    // What the signed message says. A valid signature over another document,
    // another person or another statement says nothing about this operation.
    const msg = f.mensaje;
    c.when(
      hashesEqual(msg.documentHash, m?.documento?.hash),
      "signatures",
      `signer.${i}.message.hash`,
      `${who}: signed the hash of THIS document`,
      msg.documentHash,
      `They signed ${msg.documentHash}, and the package's document is ${m?.documento?.hash}.`,
    );
    c.when(
      msg.documentId === m?.documento?.id,
      "signatures",
      `signer.${i}.message.id`,
      `${who}: signed this operation`,
      msg.documentId,
      `The message says ${JSON.stringify(msg.documentId)} and the operation is ${JSON.stringify(m?.documento?.id)}.`,
    );
    c.when(
      String(msg.signerEmail).toLowerCase() === String(f.email ?? "").toLowerCase(),
      "signatures",
      `signer.${i}.message.email`,
      `${who}: signed under their own email`,
      msg.signerEmail,
      `The message says ${msg.signerEmail} and the signer is ${f.email}.`,
    );
    c.when(
      msg.statement === STATEMENT,
      "signatures",
      `signer.${i}.message.statement`,
      `${who}: accepted sygners' statement`,
      msg.statement,
      `They accepted a different text: ${JSON.stringify(msg.statement)}.`,
    );

    // THE check: the address comes out of the signature.
    const r = recoverSigner(msg, f.firma, chainId);
    if (!r.ok) {
      c.fail("signatures", `signer.${i}.recovered`, `${who}: their signature can be verified`, r.error);
    } else {
      c.when(
        sameAddress(r.address, f.wallet),
        "signatures",
        `signer.${i}.recovered`,
        `${who}: the address recovered from their signature is the declared one`,
        r.address,
        `The signature was produced by ${r.address}, and the manifest declares ${f.wallet}.`,
        { expected: f.wallet ?? null, got: r.address },
      );
    }

    // And the fingerprint, which is the half that was written to the chain.
    const fp = fingerprint(f.firma);
    if (f.sigHash) {
      c.when(
        hashesEqual(fp, f.sigHash),
        "signatures",
        `signer.${i}.fingerprint`,
        `${who}: the declared fingerprint is their signature's`,
        fp,
        `keccak256 of the signature gives ${fp} and the manifest declares ${f.sigHash}.`,
      );
    } else {
      c.warn("signatures", `signer.${i}.fingerprint`, `${who}: the manifest declares their signature's fingerprint`, "It does not; it is recomputed from the signature to cross-check against the chain.");
    }

    // The timestamp is asserted by whoever signs; `firmadoEl` is the server's
    // clock. Being far apart does not invalidate the signature, but it is said.
    const declared = date(f.firmadoEl);
    if (declared && Number.isFinite(Number(msg.timestamp))) {
      const delta = Math.abs(secs(declared) - Number(msg.timestamp));
      c[delta <= TOLERANCE_SECONDS ? "ok" : "warn"](
        "signatures",
        `signer.${i}.message.date`,
        `${who}: the date they signed and the recorded one are close`,
        delta <= TOLERANCE_SECONDS
          ? `${new Date(Number(msg.timestamp) * 1000).toISOString()} (${delta}s)`
          : `The message says ${new Date(Number(msg.timestamp) * 1000).toISOString()} and the manifest recorded ${f.firmadoEl}: ${delta}s apart.`,
      );
    }
  }
}

// ── 3.6 The private keys provided ────────────────────────────────────────────
//
// Optional, and only if somebody hands them over (`PK_SIGNER…` in the
// environment). It closes the end the package cannot: the evidence proves that
// A CERTAIN WALLET signed; the key proves that whoever gave it to you controls
// that wallet.
//
// ⚠️ It does not prove identity. A key is copied, lent and stolen: it
// establishes control of the wallet, not who the person is.
function checkKeys(c, m) {
  const keys = providedKeys();
  const signers = Array.isArray(m.firmantes) ? m.firmantes : [];

  // With no keys the report has to say so rather than simply not mention it:
  // "VERIFIED" without this line reads as if it had been established who each
  // signer is, and what was established is that CERTAIN WALLETS signed.
  if (keys.length === 0) {
    const who = signers.map((f) => f.email).filter(Boolean).join(", ");
    c.warn(
      "keys",
      "keys.none-provided",
      "No signer private keys were provided",
      `It is proven that the declared wallets signed this document${who ? ` (${who})` : ""}, but not who controls them today. To confirm that, put each signer's key in PK_SIGNER1, PK_SIGNER2… in the .env; or, better, ask each of them to SIGN a text you choose — it proves the same without anyone handing over their key. Either way it establishes control of the wallet, not identity.`,
    );
    return;
  }

  const issuer = m?.emisor;
  let matches = 0;

  for (const k of keys) {
    if (k.error) {
      c.fail("keys", `key.${k.name}`, `${k.name}: is a private key`, k.error);
      continue;
    }

    const signer = signers.find((f) => sameAddress(f.wallet, k.address));
    if (signer) {
      matches++;
      // If the address was also recovered from their signature, the chain is
      // complete: this key controls the wallet that produced that signature.
      const recovered = c.list.find(
        (x) => x.id === `signer.${signers.indexOf(signer)}.recovered` && x.state === "ok",
      );
      c.ok(
        "keys",
        `key.${k.name}`,
        `${k.name}: controls ${signer.email}'s wallet`,
        recovered
          ? `${k.address} — and that wallet is the one that produced the signature, so whoever provided this key is the one who signed. It establishes control of the wallet, not identity.`
          : `${k.address} — it is that signer's declared wallet. The raw signature is not in the package, so the link to the signature rests on the on-chain attestation.`,
      );
      continue;
    }

    if (issuer && sameAddress(issuer.wallet, k.address)) {
      matches++;
      c.ok(
        "keys",
        `key.${k.name}`,
        `${k.name}: controls the issuer's wallet`,
        `${k.address} — that is the REGISTRATION's wallet, which signs nothing. It confirms who created the operation, not who signed it.`,
      );
      continue;
    }

    c.warn(
      "keys",
      `key.${k.name}`,
      `${k.name}: corresponds to some wallet in this package`,
      `It derives to ${k.address}, which is none of this operation's wallets. If you expected a signer's wallet, it is not; if the same .env is used for several packages, it belongs to another one.`,
    );
  }

  // All wrong is different from some wrong: a shared .env explains the second,
  // not the first.
  const valid = keys.filter((k) => !k.error).length;
  if (valid > 0 && matches === 0) {
    c.fail(
      "keys",
      "keys.no-match",
      "At least one provided key belongs to this package",
      `${valid} key(s) were provided and none controls a wallet of this operation. Either they belong to another package, or this one's wallets are not what you thought.`,
    );
  }

  // Who was not confirmed. Not a failure —keys are optional— but staying quiet
  // would let "verified" read as "everyone was confirmed".
  const unconfirmed = signers.filter(
    (f) => !keys.some((k) => k.address && sameAddress(f.wallet, k.address)),
  );
  if (matches > 0 && unconfirmed.length > 0) {
    c.info(
      "keys",
      "keys.missing",
      "Signers with no key provided",
      `${unconfirmed.map((f) => f.email).join(", ")} — their signature is verified all the same; what was not confirmed is who controls that wallet today.`,
    );
  }
}

// ── 4. The chain ─────────────────────────────────────────────────────────────
async function checkChain(c, m) {
  const chainId = Number(m?.cadena?.chainId);
  const chain = chainFor(chainId);
  const expected = expectations(chainId);
  const result = { chain, attestations: {} };

  if (!chain.known) {
    c.warn(
      "chain",
      "chain.known",
      "The manifest's chain is known",
      `chainId ${chainId} is not in the verifier's table. Configure RPC_URL_${chainId}, EAS_CONTRACT_ADDRESS_${chainId} and SCHEMA_REGISTRY_ADDRESS_${chainId}.`,
    );
  } else {
    c.ok("chain", "chain.known", "The manifest's chain is known", `${chain.name} (chainId ${chainId})`);
  }
  if (chain.testnet) {
    c.warn(
      "chain",
      "chain.testnet",
      "The evidence is anchored on a TEST NETWORK",
      `${chain.name} is a TEST NETWORK. The anchoring is checked all the same and everything below holds, but a testnet costs nothing to produce and can be restarted entirely: as proof that the document existed on that date, it does not carry the weight of a production network. A package that has to stand up to a third party should be anchored on a production network.`,
    );
  }
  if (!chain.ownRpc) {
    c.warn(
      "chain",
      "chain.rpc",
      "The RPC is one you control",
      `The default public node was used (${chain.rpcUrl}). It works for verifying, but for a verification that has to stand up to a third party, point at your own node with RPC_URL_${chainId}.`,
    );
  }
  if (!chain.rpcUrl || !chain.eas) {
    c.fail(
      "chain",
      "chain.config",
      "There is something to query the chain with",
      `Missing ${!chain.rpcUrl ? `RPC_URL_${chainId}` : `EAS_CONTRACT_ADDRESS_${chainId}`}.`,
    );
    return result;
  }

  const prov = provider(chain, RPC_TIMEOUT_MS);
  try {
    const nodeId = await nodeChainId(prov);
    if (nodeId !== chainId) {
      c.fail(
        "chain",
        "chain.id",
        "The RPC node is on the chain the manifest declares",
        `The manifest says ${chainId} and the node answers ${nodeId}. Nothing is verified against the wrong network.`,
      );
      return result;
    }
    c.ok("chain", "chain.id", "The RPC node is on the chain the manifest declares", `chainId ${nodeId}`);
  } catch (e) {
    c.fail("chain", "chain.id", "The RPC node answers", `${chain.rpcUrl}: ${e?.shortMessage ?? e?.message ?? e}`);
    return result;
  }

  // 4.1 The document's registration.
  const regUid = m?.cadena?.registroUid;
  let registration = null;
  if (!isHex32(regUid)) {
    c.fail("chain", "registration.uid", "The manifest carries the registration UID", `${JSON.stringify(regUid)} is not a UID.`);
  } else {
    registration = await readOne(c, prov, chain, regUid, "registration", "The document's registration exists on chain");
  }

  if (registration) {
    result.attestations.registration = registration;
    const d = decodeData(registration.data);
    if (!d.ok) {
      c.fail("chain", "registration.data", "The registration decodes with sygners' schema", d.error);
    } else {
      c.when(
        hashesEqual(d.documentHash, m?.documento?.hash),
        "chain",
        "registration.hash",
        "The anchored hash is the package document's",
        d.documentHash,
        `The chain has ${d.documentHash} anchored and the package declares ${m?.documento?.hash}.`,
        { expected: m?.documento?.hash ?? null, got: d.documentHash },
      );
      c.when(
        d.action === ACTION_REGISTER,
        "chain",
        "registration.action",
        "The registration attestation says REGISTER",
        d.action,
        `It says "${d.action}".`,
      );
      c.when(
        d.email?.toLowerCase() === String(m?.emisor?.email ?? "").toLowerCase(),
        "chain",
        "registration.issuer.email",
        "The anchored issuer is the manifest's",
        d.email,
        `On chain: ${d.email}. In the manifest: ${m?.emisor?.email}.`,
      );
      c.when(
        addr(d.subject) && addr(d.subject) === addr(m?.emisor?.wallet),
        "chain",
        "registration.issuer.wallet",
        "The anchored issuer wallet is the manifest's",
        d.subject,
        `On chain: ${d.subject}. In the manifest: ${m?.emisor?.wallet}.`,
      );
    }
    await checkSchema(c, prov, chain, registration.schema, expected);
    checkAttester(c, registration.attester, expected, "registration");
  }

  // 4.2 Each signature.
  const signers = Array.isArray(m.firmantes) ? m.firmantes : [];
  result.attestations.signatures = [];
  for (const [i, f] of signers.entries()) {
    const who = f.email ?? `signer ${i + 1}`;
    if (!isHex32(f.attestationUid)) {
      c.fail("signatures", `signer.${i}.uid`, `${who}: the manifest carries their signature UID`, `${JSON.stringify(f.attestationUid)} is not a UID.`);
      continue;
    }
    const a = await readOne(c, prov, chain, f.attestationUid, `signer.${i}`, `${who}: their signature exists on chain`);
    if (!a) continue;
    result.attestations.signatures.push({ email: f.email, attestation: a });

    const d = decodeData(a.data);
    if (!d.ok) {
      c.fail("signatures", `signer.${i}.data`, `${who}: their signature decodes with sygners' schema`, d.error);
      continue;
    }
    c.when(
      d.action === ACTION_SIGN,
      "signatures",
      `signer.${i}.action`,
      `${who}: the attestation says SIGN`,
      d.action,
      `It says "${d.action}".`,
    );
    c.when(
      hashesEqual(d.documentHash, m?.documento?.hash),
      "signatures",
      `signer.${i}.hash`,
      `${who}: the hash in their attestation is this document's`,
      d.documentHash,
      `Their signature is anchored over ${d.documentHash}, which is not this package's document.`,
    );
    c.when(
      d.email?.toLowerCase() === String(f.email ?? "").toLowerCase(),
      "signatures",
      `signer.${i}.email`,
      `${who}: the anchored email is the manifest's`,
      d.email,
      `On chain: ${d.email}. In the manifest: ${f.email}.`,
    );
    c.when(
      addr(d.subject) && addr(d.subject) === addr(f.wallet),
      "signatures",
      `signer.${i}.wallet`,
      `${who}: the anchored wallet is the manifest's`,
      d.subject,
      `On chain: ${d.subject}. In the manifest: ${f.wallet}.`,
    );
    // The anchored fingerprint. With format 2 this stops being "something is
    // written there" and becomes the knot of the whole evidence: the signature
    // in the package is, byte for byte, the one anchored on chain.
    const packageFingerprint = isWellFormedSignature(f.firma) ? fingerprint(f.firma) : null;
    if (packageFingerprint) {
      c.when(
        hashesEqual(d.sigHash, packageFingerprint),
        "signatures",
        `signer.${i}.sighash`,
        `${who}: the package's signature is the one that was anchored`,
        d.sigHash,
        `The chain holds fingerprint ${d.sigHash} and the signature in the package gives ${packageFingerprint}: not the same signature.`,
      );
    } else {
      c.when(
        d.sigHash && d.sigHash !== ZERO_BYTES32,
        "signatures",
        `signer.${i}.sighash`,
        `${who}: the attestation carries their EIP-712 signature fingerprint`,
        d.sigHash,
        "The sigHash field is zero: the attestation binds no signature.",
      );
    }
    // The signature references the registration: that is what joins them into a
    // single file.
    if (registration) {
      c.when(
        a.refUID?.toLowerCase() === registration.uid.toLowerCase(),
        "signatures",
        `signer.${i}.ref`,
        `${who}: their signature references the document's registration`,
        a.refUID,
        `It references ${a.refUID}, not registration ${registration.uid}.`,
      );
      c.when(
        a.schema?.toLowerCase() === registration.schema?.toLowerCase(),
        "signatures",
        `signer.${i}.schema`,
        `${who}: uses the same schema as the registration`,
        a.schema,
        `Schema ${a.schema}, different from the registration's ${registration.schema}.`,
      );
    }
    checkAttester(c, a.attester, expected, `signer.${i}`, who);

    // The date the manifest declares against the one left in the block.
    const declared = date(f.firmadoEl);
    if (declared && a.time) {
      const delta = Math.abs(secs(declared) - a.time);
      const within = delta <= TOLERANCE_SECONDS;
      c[within ? "ok" : "warn"](
        "signatures",
        `signer.${i}.date`,
        `${who}: the declared date and the block's are close`,
        within
          ? `${f.firmadoEl} · on chain ${new Date(a.time * 1000).toISOString()} (${delta}s)`
          : `The manifest says ${f.firmadoEl} and the block says ${new Date(a.time * 1000).toISOString()}: ${delta}s apart. Anchoring always comes after signing, but a large gap is worth a look.`,
      );
    }
  }

  // 4.3 The transaction receipts.
  {
    const pairs = [
      ["registration", m?.cadena?.registroTxHash, "The registration"],
      ...signers.map((f, i) => [`signer.${i}`, f.txHash, f.email]),
    ];
    for (const [id, hash, label] of pairs) {
      const who = label ? `${label}: ` : "";
      if (!isHex32(hash)) {
        c.warn("chain", `${id}.tx`, `${who}has a transaction hash`, `${JSON.stringify(hash)} is not a hash.`);
        continue;
      }
      try {
        const r = await readReceipt(prov, hash);
        if (!r) {
          c.fail("chain", `${id}.tx`, `${who}the transaction exists on chain`, `There is no receipt for ${hash}.`);
        } else if (r.status !== 1) {
          c.fail("chain", `${id}.tx`, `${who}the transaction executed successfully`, `status ${r.status}.`);
        } else if (addr(r.to) !== addr(chain.eas)) {
          c.fail(
            "chain",
            `${id}.tx`,
            `${who}the transaction went to the EAS contract`,
            `It went to ${r.to}, not to ${chain.eas}.`,
          );
        } else {
          c.ok("chain", `${id}.tx`, `${who}the transaction exists and went to EAS`, `block ${r.blockNumber} · ${hash}`);
        }
      } catch (e) {
        c.warn("chain", `${id}.tx`, `${who}the receipt could be requested`, e?.shortMessage ?? e?.message ?? String(e));
      }
    }
  }

  return result;
}

async function readOne(c, prov, chain, uid, id, title) {
  try {
    const a = await readAttestation(prov, chain, uid);
    if (!a) {
      c.fail(
        "chain",
        `${id}.exists`,
        title,
        `There is no attestation with UID ${uid} on ${chain.name}. Either the package made it up, or it was anchored on another network.`,
      );
      return null;
    }
    if (a.revocationTime && a.revocationTime > 0) {
      c.fail(
        "chain",
        `${id}.exists`,
        title,
        `It exists, but it was REVOKED on ${new Date(a.revocationTime * 1000).toISOString()}.`,
      );
      return a;
    }
    if (a.expirationTime && a.expirationTime > 0 && a.expirationTime * 1000 < Date.now()) {
      c.warn("chain", `${id}.exists`, title, `It exists, but it expired on ${new Date(a.expirationTime * 1000).toISOString()}.`);
      return a;
    }
    c.ok("chain", `${id}.exists`, title, `${uid} · anchored on ${new Date(a.time * 1000).toISOString()} · ${chain.attestationUrl(uid) ?? ""}`.trim());
    return a;
  } catch (e) {
    c.fail("chain", `${id}.exists`, title, `Could not query: ${e?.shortMessage ?? e?.message ?? e}`);
    return null;
  }
}

function checkAttester(c, attester, expected, id, label) {
  const who = label ? `${label}: ` : "";
  if (!expected.attester) {
    c.info("chain", `${id}.attester`, `${who}who anchored it`, `${attester} (set SYGNERS_ATTESTER to require a specific one)`);
    return;
  }
  c.when(
    addr(attester) && addr(attester) === addr(expected.attester),
    "chain",
    `${id}.attester`,
    `${who}it was anchored by the expected attester`,
    attester,
    `It was anchored by ${attester}, and you expected ${expected.attester}.`,
  );
}

async function checkSchema(c, prov, chain, schemaUid, expected) {
  if (expected.schemaUid) {
    c.when(
      schemaUid?.toLowerCase() === expected.schemaUid.toLowerCase(),
      "chain",
      "schema.uid",
      "The attestations use the expected schema",
      schemaUid,
      `They use ${schemaUid} and you expected ${expected.schemaUid}.`,
    );
  } else {
    c.info("chain", "schema.uid", "Schema used", `${schemaUid} (set EAS_SCHEMA_UID to require one)`);
  }
  if (!chain.registry) return;
  try {
    const s = await readSchema(prov, chain, schemaUid);
    if (!s) {
      c.warn("chain", "schema.definition", "The schema is registered on chain", `${schemaUid} was not found in the SchemaRegistry.`);
      return;
    }
    const norm = (t) => String(t).replace(/\s+/g, " ").trim();
    c.when(
      norm(s.schema) === norm(SCHEMA_DEFINITION),
      "chain",
      "schema.definition",
      "The on-chain schema is sygners'",
      s.schema,
      `On chain: "${s.schema}". Expected: "${SCHEMA_DEFINITION}".`,
    );
  } catch (e) {
    c.warn("chain", "schema.definition", "The registry's schema could be read", e?.shortMessage ?? e?.message ?? String(e));
  }
}

// ── Orchestration ────────────────────────────────────────────────────────────
export async function verifyEvidence(bytes, opts) {
  const c = new Checks();
  const zip = openEvidence(bytes);

  if (!zip.ok) {
    c.fail("package", "zip", "The file is a readable .zip", zip.error);
    return buildResult(c, { opts, zip: null, manifest: null, mock: { mock: false, reasons: [] } });
  }

  checkStructure(c, zip);

  const m = zip.manifest;
  if (!m) {
    c.fail("manifest", "manifest.json", "The manifest can be read", zip.manifestError);
    return buildResult(c, { opts, zip, manifest: null, mock: { mock: false, reasons: [] } });
  }
  c.ok("manifest", "manifest.json", "The manifest can be read", `${zip.rawManifest.length} bytes of JSON`);

  checkManifest(c, m);
  const computedHash = checkDocument(c, zip, m);

  // Signatures are verified WITHOUT a network: since format 2, a package proves
  // on its own that those wallets signed — recovering the address needs no
  // chain, only the signature and the message.
  checkRawSignatures(c, m);
  checkKeys(c, m);

  // Mock evidence is detected WITHOUT a network, and before touching it: if the
  // package came from an environment with no chain, querying the chain will
  // only confirm there is nothing there, and the report has to say why.
  const mock = detectMock(m);
  if (mock.mock) {
    c.fail(
      "chain",
      "chain.mock",
      "The evidence is really anchored (not mock mode)",
      `This package's on-chain identifiers are the ones sygners generates when it has NO chain configured: ${mock.reasons.join("; ")}. The document and the manifest may be correct, but NOTHING is anchored: this does not prove the document existed on any date.`,
    );
  }

  let chain = null;
  if (opts.offline) {
    c.skip("chain", "chain", "Cross-checking against the chain", "Requested with OFFLINE=true.");
  } else if (mock.mock) {
    c.skip("chain", "chain", "Cross-checking against the chain", "Not queried: the identifiers are mock ones.");
  } else {
    chain = await checkChain(c, m);
  }

  return buildResult(c, { opts, zip, manifest: m, mock, computedHash, chain });
}

function buildResult(c, ctx) {
  const fails = c.count("fail");
  const warns = c.count("warn");
  const skipped = c.count("skipped");

  let verdict;
  if (fails > 0) verdict = ctx.mock?.mock ? "MOCK" : "FAILED";
  else if (ctx.opts.offline) verdict = "PARTIAL";
  else verdict = "VERIFIED";

  const m = ctx.manifest;
  const chainId = Number(m?.cadena?.chainId);
  const cfg = Number.isFinite(chainId) ? chainFor(chainId) : null;

  return {
    verdict,
    summary: { ok: c.count("ok"), fails, warns, skipped },
    checks: c.list,
    operation: m
      ? {
          format: m.formato ?? null,
          documentId: m.documento?.id ?? null,
          title: m.documento?.titulo ?? null,
          file: ctx.zip?.documentName ?? null,
          size: ctx.zip?.document?.length ?? m.documento?.tamano ?? null,
          declaredHash: m.documento?.hash ?? null,
          computedHash: ctx.computedHash ?? null,
          chainId: Number.isFinite(chainId) ? chainId : null,
          network: cfg?.name ?? null,
          registrationUid: m.cadena?.registroUid ?? null,
          registrationUrl: cfg?.attestationUrl(m.cadena?.registroUid) ?? null,
          // Both come from the CHAIN, not from the package: they are what was
          // checked, not what the manifest claims.
          attester: ctx.chain?.attestations?.registration?.attester ?? null,
          schemaUid: ctx.chain?.attestations?.registration?.schema ?? null,
          issuer: m.emisor ?? null,
          signers: (m.firmantes ?? []).map((f) => ({
            email: f.email ?? null,
            wallet: f.wallet ?? null,
            state: f.estado ?? null,
            signedAt: f.firmadoEl ?? null,
            attestationUid: f.attestationUid ?? null,
            txHash: f.txHash ?? null,
            sigHash: f.sigHash ?? null,
            signature: f.firma ?? null,
            url: cfg?.attestationUrl(f.attestationUid) ?? null,
          })),
          dates: m.fechas ?? null,
          generatedAt: m.generadoEl ?? null,
          mock: Boolean(ctx.mock?.mock),
        }
      : null,
  };
}
