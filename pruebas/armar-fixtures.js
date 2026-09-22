// Arma paquetes de evidencia de prueba, con la misma forma que los que produce
// sygners (mismos nombres de archivo, mismo manifiesto, mismo zip sin comprimir).
//
// Existe para poder ejercitar el verificador sin tener la plataforma corriendo
// —que es, después de todo, la premisa del programa— y para fijar los tres
// casos que importan: uno simulado, uno manipulado y uno que afirma estar
// anclado en una cadena real.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync, strToU8 } from "fflate";
import { Wallet, keccak256 } from "ethers";
import { sha256Hex } from "../src/hash.js";
import { uidSimuladoDeRegistro, txSimuladoDeRegistro, uidSimuladoDeFirma } from "../src/simulado.js";
import { DECLARACION, TIPOS_FIRMA, dominioCanonico } from "../src/firma.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

function leeme(m, nombreDocumento) {
  const firmantes = m.firmantes
    .map((f) => `  - ${f.email}${f.wallet ? ` (${f.wallet})` : ""}${f.firmadoEl ? ` — ${f.firmadoEl}` : ""}`)
    .join("\n");
  return `ARCHIVO DE EVIDENCIA — sygners
==============================

Operación: ${m.documento.titulo}
Generado:  ${m.generadoEl}

Cómo comprobar que esto es auténtico, sin depender de sygners
-------------------------------------------------------------
1. Calculá el SHA-256 de "${nombreDocumento}". Tiene que dar:
       ${m.documento.hash}

2. Ese mismo hash está registrado en la cadena ${m.cadena.chainId}, en la
   attestation ${m.cadena.registroUid ?? "(sin registro on-chain)"}.

Firmantes
---------
${firmantes || "  (sin firmantes)"}
`;
}

function manifiesto({ id, hash, chainId, registroUid, registroTxHash, firmantes, nombreArchivo, tamano }) {
  const creado = new Date("2026-09-01T12:00:00.000Z");
  const firmado = new Date("2026-09-01T12:30:00.000Z");
  return {
    formato: 1,
    documento: {
      id,
      titulo: "Contrato de prueba",
      nombreArchivo,
      tipo: "text/plain",
      tamano,
      hash,
    },
    cadena: { chainId, registroUid, registroTxHash },
    emisor: { email: "emisor@example.com", wallet: "0x0000000000000000000000000000000000000001" },
    firmantes: firmantes.map((f) => ({ ...f, firmadoEl: firmado.toISOString(), estado: "SIGNED" })),
    fechas: {
      creado: creado.toISOString(),
      ultimaFirma: firmado.toISOString(),
      vence: new Date("2026-09-08T12:30:00.000Z").toISOString(),
    },
    generadoEl: new Date("2026-09-02T09:00:00.000Z").toISOString(),
  };
}

function empaquetar({ documento, nombreDocumento, m, pdf }) {
  return zipSync(
    {
      [nombreDocumento]: [documento, { level: 0 }],
      "constancia.pdf": [pdf, { level: 0 }],
      "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
      "LEEME.txt": [strToU8(leeme(m, nombreDocumento))],
    },
    { level: 0 },
  );
}

const PDF = strToU8("%PDF-1.7\nconstancia de prueba\n%%EOF\n");
const NOMBRE = "contrato.txt";
const DOC = strToU8("CONTRATO DE PRUEBA\n" + "x".repeat(2000));

mkdirSync(DIR, { recursive: true });
const hash = sha256Hex(DOC);

// 1. Simulada: los UIDs son los deterministas del modo sin cadena.
{
  const id = "doc-simulado-1";
  const wallet = "0x0000000000000000000000000000000000000002";
  const m = manifiesto({
    id,
    hash,
    chainId: 11155111,
    registroUid: uidSimuladoDeRegistro(id),
    registroTxHash: txSimuladoDeRegistro(id),
    nombreArchivo: NOMBRE,
    tamano: DOC.length,
    firmantes: [
      {
        email: "emisor@example.com",
        wallet,
        attestationUid: uidSimuladoDeFirma(wallet, `0x${"11".repeat(32)}`),
        txHash: `0x${"22".repeat(32)}`,
      },
    ],
  });
  writeFileSync(join(DIR, "simulada.zip"), empaquetar({ documento: DOC, nombreDocumento: NOMBRE, m, pdf: PDF }));
}

// 2. Manipulada: el manifiesto es el mismo, el documento adentro es otro.
{
  const id = "doc-manipulado-1";
  const m = manifiesto({
    id,
    hash, // el hash del documento ORIGINAL
    chainId: 11155111,
    registroUid: `0x${"ab".repeat(32)}`,
    registroTxHash: `0x${"cd".repeat(32)}`,
    nombreArchivo: NOMBRE,
    tamano: DOC.length,
    firmantes: [
      {
        email: "firmante@example.com",
        wallet: "0x0000000000000000000000000000000000000003",
        attestationUid: `0x${"ef".repeat(32)}`,
        txHash: `0x${"09".repeat(32)}`,
      },
    ],
  });
  const otro = strToU8("CONTRATO DE PRUEBA\n" + "x".repeat(1999) + "y"); // un byte distinto
  writeFileSync(join(DIR, "manipulada.zip"), empaquetar({ documento: otro, nombreDocumento: NOMBRE, m, pdf: PDF }));
}

// 3. Inventada: se declara anclada en Sepolia con UIDs que no existen. Sirve
//    para ejercitar el camino de red (sin --sin-cadena).
{
  const id = "doc-inventado-1";
  const m = manifiesto({
    id,
    hash,
    chainId: 11155111,
    registroUid: `0x${"12".repeat(32)}`,
    registroTxHash: `0x${"34".repeat(32)}`,
    nombreArchivo: NOMBRE,
    tamano: DOC.length,
    firmantes: [
      {
        email: "firmante@example.com",
        wallet: "0x0000000000000000000000000000000000000004",
        attestationUid: `0x${"56".repeat(32)}`,
        txHash: `0x${"78".repeat(32)}`,
      },
    ],
  });
  writeFileSync(join(DIR, "inventada.zip"), empaquetar({ documento: DOC, nombreDocumento: NOMBRE, m, pdf: PDF }));
}

// 4. Formato 2: con la firma cruda adentro. Los UIDs on-chain son inventados
//    (no hay nada anclado), pero la FIRMA es real: con `--sin-cadena` se ve
//    que la dirección se recupera sola.
{
  const id = "doc-formato2-1";
  const w = Wallet.createRandom();
  const firmadoEl = new Date("2026-09-01T12:30:00.000Z");
  const mensaje = {
    documentId: id,
    documentHash: hash,
    signerEmail: "firmante@example.com",
    statement: DECLARACION,
    timestamp: Math.floor(firmadoEl.getTime() / 1000),
  };
  const firma = await w.signTypedData(dominioCanonico(10), TIPOS_FIRMA, mensaje);
  const m = manifiesto({
    id,
    hash,
    chainId: 10,
    registroUid: `0x${"1a".repeat(32)}`,
    registroTxHash: `0x${"2b".repeat(32)}`,
    nombreArchivo: NOMBRE,
    tamano: DOC.length,
    firmantes: [
      {
        email: "firmante@example.com",
        wallet: w.address,
        attestationUid: `0x${"3c".repeat(32)}`,
        txHash: `0x${"4d".repeat(32)}`,
      },
    ],
  });
  m.formato = 2;
  m.eip712 = { dominio: dominioCanonico(10), tipos: TIPOS_FIRMA };
  m.firmantes[0].mensaje = mensaje;
  m.firmantes[0].firma = firma;
  m.firmantes[0].sigHash = keccak256(firma);
  writeFileSync(join(DIR, "formato2.zip"), empaquetar({ documento: DOC, nombreDocumento: NOMBRE, m, pdf: PDF }));
}

console.log(`fixtures en ${DIR}: simulada.zip, manipulada.zip, inventada.zip, formato2.zip`);
