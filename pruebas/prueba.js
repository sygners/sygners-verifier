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
import { Wallet, keccak256 } from "ethers";
import { sha256Hex } from "../src/hash.js";
import { verificarEvidencia } from "../src/verificar.js";
import { opciones, SCHEMA_DEFINICION } from "../src/config.js";
import { DECLARACION, TIPOS_FIRMA, dominioCanonico } from "../src/firma.js";
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

// La configuración sale del entorno, igual que en la vida real: el verificador
// ya no toma opciones por parámetro.
function conEnv(vars, fn) {
  const previas = { ...process.env };
  for (const k of Object.keys(process.env)) {
    if (/^(RPC_URL|EAS_SCHEMA_UID|SYGNERS_ATTESTER|PK_SIGNER|SIN_CADENA)/.test(k)) delete process.env[k];
  }
  Object.assign(process.env, vars);
  return Promise.resolve(fn()).finally(() => {
    for (const k of Object.keys(process.env)) {
      if (/^(RPC_URL|EAS_SCHEMA_UID|SYGNERS_ATTESTER|PK_SIGNER|SIN_CADENA)/.test(k)) delete process.env[k];
    }
    Object.assign(process.env, previas);
  });
}

const sinCadena = (zip) => conEnv({ SIN_CADENA: "true" }, () => verificarEvidencia(zip, opciones()));

async function contra(estado, zip, extra = {}) {
  const nodo = await levantarNodo(estado);
  try {
    return await conEnv(
      // El comodín además del específico: así el caso "el nodo es de otra
      // cadena" también cae en el nodo falso y se puede probar.
      { RPC_URL: nodo.url, [`RPC_URL_${estado.chainId}`]: nodo.url, EAS_SCHEMA_UID: SCHEMA_UID, SYGNERS_ATTESTER: ATTESTER, ...extra },
      () => verificarEvidencia(zip, opciones()),
    );
  } finally {
    await nodo.cerrar();
  }
}

// ── 1. Offline, sobre los fixtures ───────────────────────────────────────────
console.log("\n--- offline ---");
{
  const leer = (n) => readFileSync(join(DIR, "fixtures", n));
  const sim = await conEnv({}, () => verificarEvidencia(leer("simulada.zip"), opciones()));
  check("un paquete del modo simulado se marca como SIMULADO", sim.veredicto === "SIMULADO", sim.veredicto);
  check("y el motivo es el UID determinista", tiene(sim, "cadena.simulado", "falla"));
  check("pero el documento sí coincide con su manifiesto", tiene(sim, "documento.hash", "ok"));

  const man = await sinCadena(leer("manipulada.zip"));
  check("un documento cambiado no verifica", man.veredicto === "NO_VERIFICA", man.veredicto);
  check("y la falla es la del hash", tiene(man, "documento.hash", "falla"));

  const parcial = await sinCadena(leer("inventada.zip"));
  check("sin cadena, el veredicto es PARCIAL y nunca VERIFICADO", parcial.veredicto === "PARCIAL", parcial.veredicto);

  const roto = await sinCadena(Buffer.from("esto no es un zip"));
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


// ── 5. Formato 2: la firma cruda ─────────────────────────────────────────────
//
// Lo que cambia: el paquete deja de pedir que se le crea a la cadena sobre
// quién firmó. La dirección se recupera de la firma, acá, sin red.
console.log("\n--- formato 2 (firma cruda) ---");
{
  const w = Wallet.createRandom();
  const mensaje = {
    documentId: "doc-1",
    documentHash: HASH,
    signerEmail: "firmante@example.com",
    statement: DECLARACION,
    timestamp: Math.floor(FIRMADO.getTime() / 1000),
  };
  const firma = await w.signTypedData(dominioCanonico(CHAIN_ID), TIPOS_FIRMA, mensaje);
  const sigHash = keccak256(firma);

  const m2 = (patch = {}, parcheFirmante = {}) => ({
    ...manifiesto(),
    formato: 2,
    eip712: { dominio: dominioCanonico(CHAIN_ID), tipos: TIPOS_FIRMA },
    firmantes: [
      {
        email: "firmante@example.com", wallet: w.address, firmadoEl: FIRMADO.toISOString(),
        attestationUid: FIRMA_UID, txHash: FIRMA_TX, estado: "SIGNED",
        mensaje, firma, sigHash, ...parcheFirmante,
      },
    ],
    ...patch,
  });

  const cadena2 = (sh = sigHash, subject = w.address) => estadoCadena({
    atestaciones: {
      [FIRMA_UID]: atestacion({
        uid: FIRMA_UID, schema: SCHEMA_UID, time: Math.floor(FIRMADO.getTime() / 1000) + 12,
        recipient: subject, attester: ATTESTER, refUID: REG_UID,
        data: datosSygners({ documentHash: HASH, action: "SIGN", email: "firmante@example.com", subject, sigHash: sh }),
      }),
    },
  });

  // Positivo, con red.
  const r = await contra(cadena2(), armar(m2()));
  check("un paquete de formato 2 coherente VERIFICA", r.veredicto === "VERIFICADO",
        `${r.veredicto}: ${r.chequeos.filter((x) => x.estado === "falla").map((x) => x.id).join(", ")}`);
  check("se recuperó la dirección desde la firma", tiene(r, "firma.0.recuperada", "ok"));
  check("el dominio EIP-712 del paquete es el de sygners", tiene(r, "firma.eip712", "ok"));
  check("la firma del paquete es la anclada on-chain", tiene(r, "firma.0.sighash", "ok"));

  // Positivo, SIN red: es lo nuevo — la firma se prueba igual.
  const off = await sinCadena(armar(m2()));
  check("sin cadena, la firma se verifica igual", tiene(off, "firma.0.recuperada", "ok") && off.veredicto === "PARCIAL", off.veredicto);

  // La firma es de otra wallet.
  const otra = Wallet.createRandom();
  const firmaAjena = await otra.signTypedData(dominioCanonico(CHAIN_ID), TIPOS_FIRMA, mensaje);
  const rAjena = await contra(cadena2(keccak256(firmaAjena), w.address), armar(m2({}, { firma: firmaAjena, sigHash: keccak256(firmaAjena) })));
  check("una firma de otra wallet no verifica", rAjena.veredicto === "NO_VERIFICA" && tiene(rAjena, "firma.0.recuperada", "falla"));

  // El mensaje dice otro documento (firma válida, documento ajeno).
  const msjAjeno = { ...mensaje, documentHash: `0x${"77".repeat(32)}` };
  const firmaOtroDoc = await w.signTypedData(dominioCanonico(CHAIN_ID), TIPOS_FIRMA, msjAjeno);
  const rOtro = await contra(cadena2(keccak256(firmaOtroDoc)), armar(m2({}, { mensaje: msjAjeno, firma: firmaOtroDoc, sigHash: keccak256(firmaOtroDoc) })));
  check("una firma válida sobre OTRO documento no verifica", rOtro.veredicto === "NO_VERIFICA" && tiene(rOtro, "firma.0.mensaje.hash", "falla"));

  // Dominio a medida: una firma hecha en otra cadena, con el eip712 del paquete
  // retocado para que recupere limpia.
  const firmaOtraRed = await w.signTypedData(dominioCanonico(1), TIPOS_FIRMA, mensaje);
  const rDom = await contra(
    cadena2(keccak256(firmaOtraRed)),
    armar(m2({ eip712: { dominio: dominioCanonico(1), tipos: TIPOS_FIRMA } }, { firma: firmaOtraRed, sigHash: keccak256(firmaOtraRed) })),
  );
  check("un dominio EIP-712 a medida no cuela", rDom.veredicto === "NO_VERIFICA" && tiene(rDom, "firma.eip712", "falla"));
  check("   y la recuperación corre igual con el dominio canónico", tiene(rDom, "firma.0.recuperada", "falla"));

  // La firma del paquete no es la que se ancló.
  const rSig = await contra(cadena2(`0x${"aa".repeat(32)}`), armar(m2()));
  check("si la huella anclada es otra, no verifica", rSig.veredicto === "NO_VERIFICA" && tiene(rSig, "firma.0.sighash", "falla"));

  // La declaración firmada es otra.
  const msjOtroTexto = { ...mensaje, statement: "Acepto cualquier cosa." };
  const firmaOtroTexto = await w.signTypedData(dominioCanonico(CHAIN_ID), TIPOS_FIRMA, msjOtroTexto);
  const rTexto = await contra(cadena2(keccak256(firmaOtroTexto)), armar(m2({}, { mensaje: msjOtroTexto, firma: firmaOtroTexto, sigHash: keccak256(firmaOtroTexto) })));
  check("una declaración distinta no verifica", rTexto.veredicto === "NO_VERIFICA" && tiene(rTexto, "firma.0.mensaje.declaracion", "falla"));

  // Sin firma cruda: aviso, no falla. Es una operación vieja, no un paquete roto.
  const rVieja = await contra(cadena2(`0x${"ee".repeat(32)}`), armar(m2({}, { mensaje: null, firma: null, sigHash: null })));
  check("un firmante sin firma cruda avisa pero no invalida", tiene(rVieja, "firma.0.cruda", "aviso") && rVieja.veredicto === "VERIFICADO", rVieja.veredicto);

  // Formato 1: el bloque entero se omite, sin ensuciar el veredicto.
  const r1 = await contra(estadoCadena(), armar(manifiesto()));
  check("un manifiesto de formato 1 omite el bloque de firma cruda", tiene(r1, "firma.crudas", "omitido") && r1.veredicto === "VERIFICADO");
}


// ── 6. Las claves privadas aportadas ─────────────────────────────────────────
//
// Lo que se prueba acá no es la criptografía —es derivar una dirección— sino la
// política: qué se considera confirmación, qué se considera aviso y qué hace
// fallar. Y que la clave no aparezca en ningún lado de la salida.
console.log("\n--- claves aportadas ---");
{
  const w = Wallet.createRandom();
  const mensaje = {
    documentId: "doc-1", documentHash: HASH, signerEmail: "firmante@example.com",
    statement: DECLARACION, timestamp: Math.floor(FIRMADO.getTime() / 1000),
  };
  const firma = await w.signTypedData(dominioCanonico(CHAIN_ID), TIPOS_FIRMA, mensaje);
  const sigHash = keccak256(firma);
  const paquete = armar({
    ...manifiesto(), formato: 2,
    eip712: { dominio: dominioCanonico(CHAIN_ID), tipos: TIPOS_FIRMA },
    firmantes: [{
      email: "firmante@example.com", wallet: w.address, firmadoEl: FIRMADO.toISOString(),
      attestationUid: FIRMA_UID, txHash: FIRMA_TX, estado: "SIGNED", mensaje, firma, sigHash,
    }],
  });
  const cadenaConFirma = estadoCadena({
    atestaciones: {
      [FIRMA_UID]: atestacion({
        uid: FIRMA_UID, schema: SCHEMA_UID, time: Math.floor(FIRMADO.getTime() / 1000) + 12,
        recipient: w.address, attester: ATTESTER, refUID: REG_UID,
        data: datosSygners({ documentHash: HASH, action: "SIGN", email: "firmante@example.com", subject: w.address, sigHash }),
      }),
    },
  });

  const conClaves = (vars, zip = paquete, estado = cadenaConFirma) => contra(estado, zip, vars);

  const r = await conClaves({ PK_SIGNER1: w.privateKey });
  check("la clave del firmante lo confirma", r.veredicto === "VERIFICADO" && tiene(r, "clave.PK_SIGNER1", "ok"), r.veredicto);
  check("y la clave no aparece en ningún lado de la salida",
        !JSON.stringify(r).toLowerCase().includes(w.privateKey.slice(2).toLowerCase()));

  const sinPrefijo = await conClaves({ PK_SIGNER1: w.privateKey.slice(2) });
  check("una clave sin el 0x adelante también se acepta", tiene(sinPrefijo, "clave.PK_SIGNER1", "ok"));

  const ajena = await conClaves({ PK_SIGNER1: Wallet.createRandom().privateKey });
  check("una clave que no es de nadie del paquete no verifica",
        ajena.veredicto === "NO_VERIFICA" && tiene(ajena, "claves.ninguna", "falla"));

  const mixta = await conClaves({ PK_SIGNER1: w.privateKey, PK_SIGNER2: Wallet.createRandom().privateKey });
  check("con una que sí y una que no, la que no es aviso y no invalida",
        mixta.veredicto === "VERIFICADO" && tiene(mixta, "clave.PK_SIGNER2", "aviso"), mixta.veredicto);

  const rota = await conClaves({ PK_SIGNER1: w.privateKey, PK_SIGNER2: "no-es-una-clave" });
  check("una variable con basura adentro falla", tiene(rota, "clave.PK_SIGNER2", "falla"));
  check("   y tampoco imprime lo que le pusieron", !JSON.stringify(rota).includes("no-es-una-clave"));

  const nombreLibre = await conClaves({ PK_SIGNER_ANA: w.privateKey });
  check("el sufijo de la variable es libre (PK_SIGNER_ANA)", tiene(nombreLibre, "clave.PK_SIGNER_ANA", "ok"));

  const sinClaves = await conClaves({});
  check("sin claves aportadas no se agrega ningún chequeo",
        !sinClaves.chequeos.some((x) => x.area === "claves") && sinClaves.veredicto === "VERIFICADO");
}

console.log(`\n${fallas === 0 ? "todo en verde" : `${fallas} FALLAS`}\n`);
process.exit(fallas === 0 ? 0 : 1);
