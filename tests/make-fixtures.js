// Builds test evidence packages with the same shape as the ones sygners
// produces (same file names, same manifest, same uncompressed zip).
//
// It exists so the verifier can be exercised without the platform running —
// which is, after all, the premise of the program — and to pin down the cases
// that matter: a mock one, a tampered one, and one claiming to be anchored on a
// real chain.
//
// ⚠️ The manifest's keys are in Spanish because they are DATA: that is what
// sygners writes, and a fixture that renamed them would not be testing anything.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync, strToU8 } from "fflate";
import { Wallet, keccak256 } from "ethers";
import { sha256Hex } from "../src/hash.js";
import { mockRegistrationUid, mockRegistrationTx, mockSignatureUid } from "../src/mock.js";
import { STATEMENT, SIGNATURE_TYPES, canonicalDomain } from "../src/signature.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// The LEEME.txt stays in Spanish: it imitates the file sygners writes, and the
// verifier checks that the hash written in it matches the manifest's.
function readmeText(m, documentName) {
  const signers = m.firmantes
    .map((f) => `  - ${f.email}${f.wallet ? ` (${f.wallet})` : ""}${f.firmadoEl ? ` — ${f.firmadoEl}` : ""}`)
    .join("\n");
  return `ARCHIVO DE EVIDENCIA — sygners
==============================

Operación: ${m.documento.titulo}
Generado:  ${m.generadoEl}

Cómo comprobar que esto es auténtico, sin depender de sygners
-------------------------------------------------------------
1. Calculá el SHA-256 de "${documentName}". Tiene que dar:
       ${m.documento.hash}

2. Ese mismo hash está registrado en la cadena ${m.cadena.chainId}, en la
   attestation ${m.cadena.registroUid ?? "(sin registro on-chain)"}.

Firmantes
---------
${signers || "  (sin firmantes)"}
`;
}

function manifest({ id, hash, chainId, registrationUid, registrationTx, signers, fileName, size }) {
  const created = new Date("2026-09-01T12:00:00.000Z");
  const signed = new Date("2026-09-01T12:30:00.000Z");
  return {
    formato: 1,
    documento: {
      id,
      titulo: "Test contract",
      nombreArchivo: fileName,
      tipo: "text/plain",
      tamano: size,
      hash,
    },
    cadena: { chainId, registroUid: registrationUid, registroTxHash: registrationTx },
    emisor: { email: "issuer@example.com", wallet: "0x0000000000000000000000000000000000000001" },
    firmantes: signers.map((f) => ({ ...f, firmadoEl: signed.toISOString(), estado: "SIGNED" })),
    fechas: {
      creado: created.toISOString(),
      ultimaFirma: signed.toISOString(),
      vence: new Date("2026-09-08T12:30:00.000Z").toISOString(),
    },
    generadoEl: new Date("2026-09-02T09:00:00.000Z").toISOString(),
  };
}

function pack({ document, documentName, m, pdf }) {
  return zipSync(
    {
      [documentName]: [document, { level: 0 }],
      "constancia.pdf": [pdf, { level: 0 }],
      "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
      "LEEME.txt": [strToU8(readmeText(m, documentName))],
    },
    { level: 0 },
  );
}

const PDF = strToU8("%PDF-1.7\ntest certificate\n%%EOF\n");
const NAME = "contract.txt";
const DOC = strToU8("TEST CONTRACT\n" + "x".repeat(2000));

mkdirSync(DIR, { recursive: true });
const hash = sha256Hex(DOC);

// 1. Mock: the UIDs are the deterministic ones of chainless mode.
{
  const id = "doc-mock-1";
  const wallet = "0x0000000000000000000000000000000000000002";
  const m = manifest({
    id,
    hash,
    chainId: 11155111,
    registrationUid: mockRegistrationUid(id),
    registrationTx: mockRegistrationTx(id),
    fileName: NAME,
    size: DOC.length,
    signers: [
      {
        email: "issuer@example.com",
        wallet,
        attestationUid: mockSignatureUid(wallet, `0x${"11".repeat(32)}`),
        txHash: `0x${"22".repeat(32)}`,
      },
    ],
  });
  writeFileSync(join(DIR, "mock.zip"), pack({ document: DOC, documentName: NAME, m, pdf: PDF }));
}

// 2. Tampered: same manifest, a different document inside.
{
  const id = "doc-tampered-1";
  const m = manifest({
    id,
    hash, // the ORIGINAL document's hash
    chainId: 11155111,
    registrationUid: `0x${"ab".repeat(32)}`,
    registrationTx: `0x${"cd".repeat(32)}`,
    fileName: NAME,
    size: DOC.length,
    signers: [
      {
        email: "signer@example.com",
        wallet: "0x0000000000000000000000000000000000000003",
        attestationUid: `0x${"ef".repeat(32)}`,
        txHash: `0x${"09".repeat(32)}`,
      },
    ],
  });
  const other = strToU8("TEST CONTRACT\n" + "x".repeat(1999) + "y"); // one byte different
  writeFileSync(join(DIR, "tampered.zip"), pack({ document: other, documentName: NAME, m, pdf: PDF }));
}

// 3. Made up: claims to be anchored on Sepolia with UIDs that do not exist.
//    Useful to exercise the network path.
{
  const id = "doc-fabricated-1";
  const m = manifest({
    id,
    hash,
    chainId: 11155111,
    registrationUid: `0x${"12".repeat(32)}`,
    registrationTx: `0x${"34".repeat(32)}`,
    fileName: NAME,
    size: DOC.length,
    signers: [
      {
        email: "signer@example.com",
        wallet: "0x0000000000000000000000000000000000000004",
        attestationUid: `0x${"56".repeat(32)}`,
        txHash: `0x${"78".repeat(32)}`,
      },
    ],
  });
  writeFileSync(join(DIR, "fabricated.zip"), pack({ document: DOC, documentName: NAME, m, pdf: PDF }));
}

// 4. Format 2: with the raw signature inside. The on-chain UIDs are made up
//    (nothing is anchored), but the SIGNATURE is real: with OFFLINE=true you
//    can see the address recovered on its own.
{
  const id = "doc-format2-1";
  const w = Wallet.createRandom();
  const signedAt = new Date("2026-09-01T12:30:00.000Z");
  const message = {
    documentId: id,
    documentHash: hash,
    signerEmail: "signer@example.com",
    statement: STATEMENT,
    timestamp: Math.floor(signedAt.getTime() / 1000),
  };
  const signature = await w.signTypedData(canonicalDomain(10), SIGNATURE_TYPES, message);
  const m = manifest({
    id,
    hash,
    chainId: 10,
    registrationUid: `0x${"1a".repeat(32)}`,
    registrationTx: `0x${"2b".repeat(32)}`,
    fileName: NAME,
    size: DOC.length,
    signers: [
      {
        email: "signer@example.com",
        wallet: w.address,
        attestationUid: `0x${"3c".repeat(32)}`,
        txHash: `0x${"4d".repeat(32)}`,
      },
    ],
  });
  m.formato = 2;
  m.eip712 = { dominio: canonicalDomain(10), tipos: SIGNATURE_TYPES };
  m.firmantes[0].mensaje = message;
  m.firmantes[0].firma = signature;
  m.firmantes[0].sigHash = keccak256(signature);
  writeFileSync(join(DIR, "format2.zip"), pack({ document: DOC, documentName: NAME, m, pdf: PDF }));
}

console.log(`fixtures in ${DIR}: mock.zip, tampered.zip, fabricated.zip, format2.zip`);
