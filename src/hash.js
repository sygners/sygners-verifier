// The document's SHA-256: the "moment zero" of all the evidence.
//
// Same definition sygners uses (`src/lib/hash.ts`): lowercase hex with a `0x`
// prefix, over the file's bytes as they are, normalizing nothing.

import { createHash } from "node:crypto";

export function sha256Hex(bytes) {
  return `0x${createHash("sha256").update(Buffer.from(bytes)).digest("hex")}`;
}

// Comparison tolerant of case and of the prefix. A blocking check cannot fail
// over formatting.
export function hashesEqual(a, b) {
  if (!a || !b) return false;
  const norm = (h) => (String(h).startsWith("0x") ? String(h).slice(2) : String(h)).toLowerCase();
  return norm(a) === norm(b);
}
