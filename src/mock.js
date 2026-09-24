// Detecting MOCK evidence (sygners' "dev mode").
//
// When the platform is missing the relayer, the RPC or the schema UID, it
// anchors nothing: `src/lib/eas.ts` returns deterministic UIDs and tx hashes
// —`keccak256("uid:" + seed)`— so the local flow stays traceable. They are
// evidence of nothing.
//
// Such a zip is indistinguishable from a real one at a glance: it carries its
// 32-byte UIDs and its explorer links. The difference is that the UIDs can be
// RECOMPUTED without querying anything, and that is exactly what happens here.
//
// ⚠️ This is not redundant with "the attestation does not exist on chain". Both
// look the same in their outcome, but they say different things: "does not
// exist" may be the wrong RPC or the wrong network; "matches the mock UID" is
// an exact statement about where the zip came from, made without a network.

import { keccak256, toUtf8Bytes } from "ethers";

const fromSeed = (prefix, seed) => keccak256(toUtf8Bytes(`${prefix}:${seed}`));

export function mockRegistrationUid(documentId) {
  return fromSeed("uid", `register:${documentId}`);
}
export function mockRegistrationTx(documentId) {
  return fromSeed("tx", `register:${documentId}`);
}
// The signature seed includes the signature hash, which the manifest does not
// carry: it can only be recomputed if known from elsewhere. Kept for
// completeness; the "mock" verdict is decided by the registration.
export function mockSignatureUid(wallet, sigHash) {
  return fromSeed("uid", `sign:${wallet}:${sigHash}`);
}

const same = (a, b) => Boolean(a && b && a.toLowerCase() === b.toLowerCase());

// Does the manifest describe an operation anchored in mock mode?
export function detectMock(manifest) {
  const id = manifest?.documento?.id;
  if (!id) return { mock: false, reasons: [] };
  const reasons = [];
  if (same(manifest?.cadena?.registroUid, mockRegistrationUid(id))) {
    reasons.push("the registration UID is the one mock mode produces for this document");
  }
  if (same(manifest?.cadena?.registroTxHash, mockRegistrationTx(id))) {
    reasons.push("the registration transaction hash is mock mode's");
  }
  return { mock: reasons.length > 0, reasons };
}
