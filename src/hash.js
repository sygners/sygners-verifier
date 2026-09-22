// El SHA-256 del documento: el "momento cero" de toda la evidencia.
//
// Misma definición que usa sygners (`src/lib/hash.ts`): hex en minúsculas con
// prefijo `0x`, sobre los bytes del archivo tal cual, sin normalizar nada.

import { createHash } from "node:crypto";

export function sha256Hex(bytes) {
  return `0x${createHash("sha256").update(Buffer.from(bytes)).digest("hex")}`;
}

// Comparación tolerante a mayúsculas y al prefijo. Un chequeo bloqueante no
// puede fallar por formato.
export function hashesIguales(a, b) {
  if (!a || !b) return false;
  const norm = (h) => (String(h).startsWith("0x") ? String(h).slice(2) : String(h)).toLowerCase();
  return norm(a) === norm(b);
}
