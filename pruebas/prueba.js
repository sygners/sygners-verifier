// La prueba del verificador. `node pruebas/prueba.js`.
//
// Corre entera sin red y sin sygners: los paquetes se arman acá y la cadena la
// sirve un nodo JSON-RPC falso (`nodo-falso.js`). Lo que se prueba no es que el
// verificador diga que sí, sino que diga que NO cuando corresponde — que es lo
// único que hace útil a un verificador.

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync, strToU8 } from "fflate";
import { sha256Hex } from "../src/hash.js";
import { verificarEvidencia } from "../src/verificar.js";
import { opciones, SCHEMA_DEFINICION } from "../src/config.js";
import { CERO32, atestacion, datosSygners, levantarNodo } from "./nodo-falso.js";

const DIR = dirname(fileURLToPath(import.meta.url));
let fallas = 0;
const check = (etiqueta, ok, extra = "") => {
  if (!ok) fallas++;
  console.log(`${ok ? "  ok  " : " FALLA"} ${etiqueta}${extra ? ` — ${extra}` : ""}`);
};
const tiene = (r, id, estado) => r.chequeos.some((c) => c.id === id && c.estado === estado);

// ── Paquete de prueba, armado como lo arma sygners ───────────────────────────
const CHAIN_ID = 11155111;
const EAS = "0xC2679fBD37d54388Ce493F1DB75320D236e1815e";
const SCHEMA_UID = `0x${"5c".repeat(32)}`;
const ATTESTER = "0x00000000000000000000000000000000000000AA";
const EMISOR = { email: "emisor@example.com", wallet: "0x0000000000000000000000000000000000000001" };
const FIRMANTE = { email: "firmante@example.com", wallet: "0x0000000000000000000000000000000000000002" };
const REG_UID = `0x${"a1".repeat(32)}`;
const FIRMA_UID = `0x${"b2".repeat(32)}`;
const REG_TX = `0x${"c3".repeat(32)}`;
const FIRMA_TX = `0x${"d4".repeat(32)}`;
const DOC = strToU8("CONTRATO\n" + "z".repeat(500));
const HASH = sha256Hex(DOC);
const FIRMADO = new Date("2026-09-01T12:30:00.000Z");

function manifiesto(patch = {}) {
  return {
    formato: 1,
    documento: { id: "doc-1", titulo: "Contrato", nombreArchivo: "contrato.txt", tipo: "text/plain", tamano: DOC.length, hash: HASH },
    cadena: { chainId: CHAIN_ID, registroUid: REG_UID, registroTxHash: REG_TX },
    emisor: EMISOR,
    firmantes: [
      { email: FIRMANTE.email, wallet: FIRMANTE.wallet, firmadoEl: FIRMADO.toISOString(), attestationUid: FIRMA_UID, txHash: FIRMA_TX, estado: "SIGNED" },
    ],
    fechas: { creado: "2026-09-01T12:00:00.000Z", ultimaFirma: FIRMADO.toISOString(), vence: "2026-09-08T12:30:00.000Z" },
    generadoEl: "2026-09-02T09:00:00.000Z",
    ...patch,
  };
}

function armar(m, documento = DOC) {
  return zipSync(
    {
      "contrato.txt": [documento, { level: 0 }],
      "constancia.pdf": [strToU8("%PDF-1.7\n%%EOF\n"), { level: 0 }],
      "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
      "LEEME.txt": [strToU8(`Calculá el SHA-256. Tiene que dar:\n  ${m.documento.hash}\n`), { level: 0 }],
    },
    { level: 0 },
  );
}

function estadoCadena(patch = {}) {
  return {
    chainId: CHAIN_ID,
    atestaciones: {
      [REG_UID]: atestacion({
        uid: REG_UID, schema: SCHEMA_UID, time: Math.floor(FIRMADO.getTime() / 1000) - 1800,
        recipient: EMISOR.wallet, attester: ATTESTER, refUID: CERO32,
        data: datosSygners({ documentHash: HASH, action: "REGISTER", email: EMISOR.email, subject: EMISOR.wallet }),
      }),
      [FIRMA_UID]: atestacion({
        uid: FIRMA_UID, schema: SCHEMA_UID, time: Math.floor(FIRMADO.getTime() / 1000) + 12,
        recipient: FIRMANTE.wallet, attester: ATTESTER, refUID: REG_UID,
        data: datosSygners({ documentHash: HASH, action: "SIGN", email: FIRMANTE.email, subject: FIRMANTE.wallet, sigHash: `0x${"ee".repeat(32)}` }),
      }),
      ...(patch.atestaciones ?? {}),
    },
    schemas: { [SCHEMA_UID]: SCHEMA_DEFINICION, ...(patch.schemas ?? {}) },
    recibos: { [REG_TX]: { to: EAS }, [FIRMA_TX]: { to: EAS }, ...(patch.recibos ?? {}) },
  };
}

async function contra(estado, zip, flags = {}) {
  const nodo = await levantarNodo(estado);
  try {
    return await verificarEvidencia(zip, opciones({ rpc: nodo.url, schemaUid: SCHEMA_UID, attester: ATTESTER, ...flags }));
  } finally {
    await nodo.cerrar();
  }
}

// ── 1. Offline, sobre los fixtures ───────────────────────────────────────────
console.log("\n--- offline ---");
{
  const leer = (n) => readFileSync(join(DIR, "fixtures", n));
  const sim = await verificarEvidencia(leer("simulada.zip"), opciones({}));
  check("un paquete del modo simulado se marca como SIMULADO", sim.veredicto === "SIMULADO", sim.veredicto);
  check("y el motivo es el UID determinista", tiene(sim, "cadena.simulado", "falla"));
  check("pero el documento sí coincide con su manifiesto", tiene(sim, "documento.hash", "ok"));

  const man = await verificarEvidencia(leer("manipulada.zip"), opciones({ sinCadena: true }));
  check("un documento cambiado no verifica", man.veredicto === "NO_VERIFICA", man.veredicto);
  check("y la falla es la del hash", tiene(man, "documento.hash", "falla"));

  const parcial = await verificarEvidencia(leer("inventada.zip"), opciones({ sinCadena: true }));
  check("sin cadena, el veredicto es PARCIAL y nunca VERIFICADO", parcial.veredicto === "PARCIAL", parcial.veredicto);

  const roto = await verificarEvidencia(Buffer.from("esto no es un zip"), opciones({ sinCadena: true }));
  check("un archivo que no es zip no rompe el programa", roto.veredicto === "NO_VERIFICA" && tiene(roto, "zip", "falla"));
}

// ── 2. El camino positivo, contra el nodo falso ──────────────────────────────
console.log("\n--- contra la cadena (nodo falso) ---");
{
  const r = await contra(estadoCadena(), armar(manifiesto()));
  check("un paquete coherente con la cadena VERIFICA", r.veredicto === "VERIFICADO",
        `${r.veredicto}: ${r.chequeos.filter((c) => c.estado === "falla").map((c) => c.id).join(", ")}`);
  check("se confirmó el registro on-chain", tiene(r, "registro.hash", "ok"));
  check("se confirmó que la firma referencia al registro", tiene(r, "firma.0.ref", "ok"));
  check("se confirmó el schema contra el registro de schemas", tiene(r, "schema.definicion", "ok"));
  check("se confirmó el atestador esperado", tiene(r, "registro.attester", "ok"));
  check("se confirmaron los recibos de transacción", tiene(r, "registro.tx", "ok") && tiene(r, "firma.0.tx", "ok"));
}

// ── 3. Cada forma de mentir, una por una ─────────────────────────────────────
console.log("\n--- casos negativos ---");
const casos = [
  [
    "el hash anclado es otro documento",
    estadoCadena({ atestaciones: { [REG_UID]: atestacion({ uid: REG_UID, schema: SCHEMA_UID, time: 1, attester: ATTESTER, recipient: EMISOR.wallet, data: datosSygners({ documentHash: `0x${"99".repeat(32)}`, action: "REGISTER", email: EMISOR.email, subject: EMISOR.wallet }) }) } }),
    armar(manifiesto()), {}, "registro.hash",
  ],
  [
    "la atestación del registro fue revocada",
    estadoCadena({ atestaciones: { [REG_UID]: atestacion({ uid: REG_UID, schema: SCHEMA_UID, time: 1, revocationTime: 1790000000, attester: ATTESTER, recipient: EMISOR.wallet, data: datosSygners({ documentHash: HASH, action: "REGISTER", email: EMISOR.email, subject: EMISOR.wallet }) }) } }),
    armar(manifiesto()), {}, "registro.existe",
  ],
  [
    "la firma la ancló otra wallet que la del manifiesto",
    estadoCadena({ atestaciones: { [FIRMA_UID]: atestacion({ uid: FIRMA_UID, schema: SCHEMA_UID, time: 1, refUID: REG_UID, attester: ATTESTER, recipient: FIRMANTE.wallet, data: datosSygners({ documentHash: HASH, action: "SIGN", email: FIRMANTE.email, subject: "0x00000000000000000000000000000000000000ff", sigHash: `0x${"ee".repeat(32)}` }) }) } }),
    armar(manifiesto()), {}, "firma.0.wallet",
  ],
  [
    "la firma no referencia al registro de este documento",
    estadoCadena({ atestaciones: { [FIRMA_UID]: atestacion({ uid: FIRMA_UID, schema: SCHEMA_UID, time: 1, refUID: CERO32, attester: ATTESTER, recipient: FIRMANTE.wallet, data: datosSygners({ documentHash: HASH, action: "SIGN", email: FIRMANTE.email, subject: FIRMANTE.wallet, sigHash: `0x${"ee".repeat(32)}` }) }) } }),
    armar(manifiesto()), {}, "firma.0.ref",
  ],
  [
    "la ancló un atestador que no es el esperado",
    estadoCadena({ atestaciones: { [REG_UID]: atestacion({ uid: REG_UID, schema: SCHEMA_UID, time: 1, attester: "0x00000000000000000000000000000000000000bb", recipient: EMISOR.wallet, data: datosSygners({ documentHash: HASH, action: "REGISTER", email: EMISOR.email, subject: EMISOR.wallet }) }) } }),
    armar(manifiesto()), {}, "registro.attester",
  ],
  [
    "el schema on-chain no es el de sygners",
    estadoCadena({ schemas: { [SCHEMA_UID]: "string cualquierCosa" } }),
    armar(manifiesto()), {}, "schema.definicion",
  ],
  [
    "la transacción del registro no existe",
    estadoCadena({ recibos: { [REG_TX]: undefined } }),
    armar(manifiesto()), {}, "registro.tx",
  ],
  [
    "el manifiesto declara un firmante que no firmó",
    estadoCadena(),
    armar(manifiesto({ firmantes: [{ email: FIRMANTE.email, wallet: FIRMANTE.wallet, firmadoEl: null, attestationUid: FIRMA_UID, txHash: FIRMA_TX, estado: "PENDING" }] })),
    {}, "manifiesto.firmantes",
  ],
  [
    "el LEEME dice un hash y el manifiesto otro",
    estadoCadena(),
    (() => {
      const m = manifiesto();
      const z = zipSync({
        "contrato.txt": [DOC, { level: 0 }],
        "constancia.pdf": [strToU8("%PDF-1.7\n%%EOF\n"), { level: 0 }],
        "manifiesto.json": [strToU8(JSON.stringify(m, null, 2)), { level: 0 }],
        "LEEME.txt": [strToU8(`Tiene que dar:\n  0x${"00".repeat(32)}\n`), { level: 0 }],
      }, { level: 0 });
      return z;
    })(),
    {}, "documento.leeme",
  ],
];

for (const [etiqueta, estado, zip, flags, idEsperado] of casos) {
  // `recibos: {hash: undefined}` deja la clave presente; se borra para que sea
  // realmente inexistente.
  for (const [k, v] of Object.entries(estado.recibos)) if (v === undefined) delete estado.recibos[k];
  const r = await contra(estado, zip, flags);
  check(`${etiqueta} → no verifica`, r.veredicto === "NO_VERIFICA", r.veredicto);
  check(`   y lo señala en "${idEsperado}"`, tiene(r, idEsperado, "falla"),
        r.chequeos.filter((c) => c.estado === "falla").map((c) => c.id).join(", "));
}

// ── 4. Red equivocada ────────────────────────────────────────────────────────
console.log("\n--- red equivocada ---");
{
  const r = await contra({ ...estadoCadena(), chainId: 1 }, armar(manifiesto()));
  check("un nodo de otra cadena aborta el cotejo", tiene(r, "cadena.id", "falla") && r.veredicto === "NO_VERIFICA");
}

console.log(`\n${fallas === 0 ? "todo en verde" : `${fallas} FALLAS`}\n`);
process.exit(fallas === 0 ? 0 : 1);
