// La firma EIP-712 de cada firmante — lo que el formato 2 del manifiesto
// agregó y que cambia lo que un paquete puede probar por sí solo.
//
// Hasta el formato 1, la evidencia probaba que una wallet quedó ANCLADA
// firmando el documento: lo decía la attestation, y había que creerle a la
// cadena —y a quien ancló— sobre quién firmó qué. On-chain va
// `sigHash = keccak256(firma)`, o sea la huella, no la firma.
//
// Con la firma cruda y el mensaje exacto adentro del paquete, la comprobación
// se vuelve criptográfica y no necesita a nadie: se recupera la dirección desde
// la firma y tiene que dar la wallet declarada. Y `keccak256(firma)` tiene que
// dar la huella que quedó en la cadena, que es lo que ata las dos mitades.
//
// ⚠️ El dominio y los tipos se comparan contra los de ACÁ, no se toman del
// paquete. Un manifiesto adulterado podría traer un dominio elegido a medida
// para que una firma que esa wallet hizo en otro lado —otra app, otro
// contrato— recupere limpia y parezca una firma de este documento. Por eso el
// `eip712` del paquete se verifica como un dato más, y la recuperación corre
// siempre con el dominio canónico.

import { keccak256, verifyTypedData, getAddress } from "ethers";

// Copiados de `src/lib/signature.ts` de sygners. Si algún día cambian, entra
// como un `formato` nuevo del manifiesto y los dos conviven.
export const DOMINIO_NOMBRE = "sygners";
export const DOMINIO_VERSION = "1";

export const TIPOS_FIRMA = {
  DocumentSignature: [
    { name: "documentId", type: "string" },
    { name: "documentHash", type: "bytes32" },
    { name: "signerEmail", type: "string" },
    { name: "statement", type: "string" },
    { name: "timestamp", type: "uint256" },
  ],
};

export const DECLARACION =
  "Declaro haber leído y acepto firmar electrónicamente este documento.";

export function dominioCanonico(chainId) {
  return { name: DOMINIO_NOMBRE, version: DOMINIO_VERSION, chainId };
}

// ¿El `eip712` que trae el paquete es el de sygners para esta cadena?
export function compararEip712(declarado, chainId) {
  const problemas = [];
  const d = declarado?.dominio;
  if (!d) problemas.push("no trae el dominio");
  else {
    if (d.name !== DOMINIO_NOMBRE) problemas.push(`dominio.name = ${JSON.stringify(d.name)}`);
    if (String(d.version) !== DOMINIO_VERSION) problemas.push(`dominio.version = ${JSON.stringify(d.version)}`);
    if (Number(d.chainId) !== Number(chainId))
      problemas.push(`dominio.chainId = ${d.chainId}, y el documento vive en la cadena ${chainId}`);
  }
  const t = declarado?.tipos?.DocumentSignature;
  if (!Array.isArray(t)) problemas.push("no trae tipos.DocumentSignature");
  else {
    const esperado = TIPOS_FIRMA.DocumentSignature;
    const igual =
      t.length === esperado.length &&
      t.every((c, i) => c?.name === esperado[i].name && c?.type === esperado[i].type);
    if (!igual) problemas.push(`los campos del tipo no son los de sygners: ${JSON.stringify(t)}`);
  }
  return { ok: problemas.length === 0, problemas };
}

// Recupera la dirección que firmó. Siempre con el dominio canónico.
export function recuperarFirmante(mensaje, firma, chainId) {
  try {
    return { ok: true, direccion: verifyTypedData(dominioCanonico(chainId), TIPOS_FIRMA, mensaje, firma) };
  } catch (e) {
    return { ok: false, error: e?.shortMessage ?? e?.message ?? String(e) };
  }
}

// keccak256 de los bytes de la firma: exactamente lo que se ancla on-chain.
export function huella(firma) {
  try {
    return keccak256(firma);
  } catch {
    return null;
  }
}

export function esFirmaBienFormada(firma) {
  return typeof firma === "string" && /^0x[0-9a-fA-F]{130}$/.test(firma);
}

export function mismaDireccion(a, b) {
  try {
    return getAddress(String(a)) === getAddress(String(b));
  } catch {
    return false;
  }
}
