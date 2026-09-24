// Opening the evidence .zip.
//
// This reimplements sygners' `leerArchivoDeEvidencia` with one difference that
// is the whole point of this program: NOTHING here throws because something is
// missing. A zip without a manifest is not an error of the verifier, it is a
// finding of the verifier — and it has to reach the report as such, alongside
// every other check.

import { unzipSync, strFromU8 } from "fflate";

// The names sygners writes inside the package. They are data, not prose: they
// stay exactly as the platform produces them.
export const CERTIFICATE_NAME = "constancia.pdf";
export const MANIFEST_NAME = "manifiesto.json";
export const README_NAME = "LEEME.txt";

export function openEvidence(bytes) {
  let entries;
  try {
    entries = unzipSync(new Uint8Array(bytes));
  } catch (e) {
    return { ok: false, error: `Could not open the .zip: ${e?.message ?? e}` };
  }

  const files = Object.keys(entries);
  const known = new Set([CERTIFICATE_NAME, MANIFEST_NAME, README_NAME]);
  // Any entry that is not one of the three fixed ones is "the document".
  // Directories and macOS junk (`__MACOSX/`, `.DS_Store`) do not count: a zip
  // repacked by hand brings them and they are not the document.
  const candidates = files.filter(
    (n) =>
      !known.has(n) &&
      !n.endsWith("/") &&
      !n.startsWith("__MACOSX/") &&
      !n.split("/").pop().startsWith("."),
  );

  let manifest = null;
  let manifestError = null;
  if (entries[MANIFEST_NAME]) {
    try {
      manifest = JSON.parse(strFromU8(entries[MANIFEST_NAME]));
    } catch (e) {
      manifestError = `The manifest is not valid JSON: ${e?.message ?? e}`;
    }
  } else {
    manifestError = `The .zip does not contain ${MANIFEST_NAME}.`;
  }

  return {
    ok: true,
    files,
    documentCandidates: candidates,
    documentName: candidates.length === 1 ? candidates[0] : null,
    document: candidates.length === 1 ? entries[candidates[0]] : null,
    pdf: entries[CERTIFICATE_NAME] ?? null,
    readme: entries[README_NAME] ? strFromU8(entries[README_NAME]) : null,
    rawManifest: entries[MANIFEST_NAME] ?? null,
    manifest,
    manifestError,
  };
}
