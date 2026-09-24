// Each signer's EIP-712 signature — what manifest format 2 added, and what
// changes what a package can prove on its own.
//
// Up to format 1, the evidence proved that a wallet was ANCHORED signing the
// document: the attestation said so, and you had to trust the chain —and
// whoever anchored— about who signed what. What goes on chain is
// `sigHash = keccak256(signature)`, the fingerprint, not the signature.
//
// With the raw signature and the exact message inside the package, the check
// becomes cryptographic and needs nobody: the address is recovered from the
// signature and has to match the declared wallet. And `keccak256(signature)`
// has to match the fingerprint left on chain, which is what ties the two
// halves together.
//
// ⚠️ The domain and types are compared against the ones HERE; they are not
// taken from the package. A tampered manifest could carry a domain tailored so
// that a signature the wallet produced somewhere else —another app, another
// contract— recovers cleanly and looks like a signature of this document. So
// the package's `eip712` is verified like any other piece of data, and recovery
// always runs with the canonical domain.

import { keccak256, verifyTypedData, getAddress } from "ethers";

// Copied from sygners' `src/lib/signature.ts`. If they ever change, it comes in
// as a new manifest `formato` and both live side by side.
export const DOMAIN_NAME = "sygners";
export const DOMAIN_VERSION = "1";

export const SIGNATURE_TYPES = {
  DocumentSignature: [
    { name: "documentId", type: "string" },
    { name: "documentHash", type: "bytes32" },
    { name: "signerEmail", type: "string" },
    { name: "statement", type: "string" },
    { name: "timestamp", type: "uint256" },
  ],
};

// The exact sentence the signer accepts. It is Spanish because it is DATA: it
// is the text that was signed, and translating it would break every signature.
export const STATEMENT =
  "Declaro haber leído y acepto firmar electrónicamente este documento.";

export function canonicalDomain(chainId) {
  return { name: DOMAIN_NAME, version: DOMAIN_VERSION, chainId };
}

// Is the `eip712` block the package carries sygners' one for this chain?
export function compareEip712(declared, chainId) {
  const problems = [];
  const d = declared?.dominio;
  if (!d) problems.push("no domain");
  else {
    if (d.name !== DOMAIN_NAME) problems.push(`domain.name = ${JSON.stringify(d.name)}`);
    if (String(d.version) !== DOMAIN_VERSION) problems.push(`domain.version = ${JSON.stringify(d.version)}`);
    if (Number(d.chainId) !== Number(chainId))
      problems.push(`domain.chainId = ${d.chainId}, and the document lives on chain ${chainId}`);
  }
  const t = declared?.tipos?.DocumentSignature;
  if (!Array.isArray(t)) problems.push("no types.DocumentSignature");
  else {
    const expected = SIGNATURE_TYPES.DocumentSignature;
    const equal =
      t.length === expected.length &&
      t.every((f, i) => f?.name === expected[i].name && f?.type === expected[i].type);
    if (!equal) problems.push(`the type's fields are not sygners': ${JSON.stringify(t)}`);
  }
  return { ok: problems.length === 0, problems };
}

// Recovers the address that signed. Always with the canonical domain.
export function recoverSigner(message, signature, chainId) {
  try {
    return { ok: true, address: verifyTypedData(canonicalDomain(chainId), SIGNATURE_TYPES, message, signature) };
  } catch (e) {
    return { ok: false, error: e?.shortMessage ?? e?.message ?? String(e) };
  }
}

// keccak256 of the signature bytes: exactly what gets anchored on chain.
export function fingerprint(signature) {
  try {
    return keccak256(signature);
  } catch {
    return null;
  }
}

export function isWellFormedSignature(signature) {
  return typeof signature === "string" && /^0x[0-9a-fA-F]{130}$/.test(signature);
}

export function sameAddress(a, b) {
  try {
    return getAddress(String(a)) === getAddress(String(b));
  } catch {
    return false;
  }
}
