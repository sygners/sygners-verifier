// Lectura de EAS por RPC: las atestaciones y el schema, tal como están en la
// cadena, sin pasar por ningún servicio de sygners ni por easscan.
//
// Solo se usan llamadas `eth_call` y `eth_getTransactionReceipt`, que cualquier
// nodo público sirve: no hace falta un nodo de archivo ni una API key.

import { Contract, FetchRequest, JsonRpcProvider, AbiCoder, getAddress } from "ethers";

const ABI_EAS = [
  "function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
];

const ABI_REGISTRY = [
  "function getSchema(bytes32 uid) view returns (tuple(bytes32 uid, address resolver, bool revocable, string schema))",
];

// Los tipos del schema de sygners, en orden. Es lo que `SchemaEncoder` codifica
// y, por lo tanto, lo que hay que decodificar: ABI estándar, nada propietario.
const TIPOS = ["bytes32", "string", "string", "address", "bytes32"];

export function proveedor(cadena, timeoutMs) {
  const req = new FetchRequest(cadena.rpcUrl);
  req.timeout = timeoutMs;
  // Sin red fijada a propósito: queremos PREGUNTARLE el chainId al nodo y
  // compararlo con el del manifiesto, no dárselo por hecho.
  return new JsonRpcProvider(req, undefined, { polling: false, staticNetwork: false });
}

export async function chainIdDelNodo(prov) {
  const red = await prov.getNetwork();
  return Number(red.chainId);
}

export async function leerAtestacion(prov, cadena, uid) {
  const eas = new Contract(cadena.eas, ABI_EAS, prov);
  const a = await eas.getAttestation(uid);
  const vacia = a.schema === `0x${"00".repeat(32)}` && a.time === 0n;
  if (vacia) return null;
  return {
    uid: a.uid,
    schema: a.schema,
    time: Number(a.time),
    expirationTime: Number(a.expirationTime),
    revocationTime: Number(a.revocationTime),
    refUID: a.refUID,
    recipient: a.recipient,
    attester: a.attester,
    revocable: a.revocable,
    data: a.data,
  };
}

// Decodifica el payload de la atestación al schema de sygners. Si los bytes no
// corresponden a ese schema, devuelve el error en vez de tirar: es un hallazgo.
export function decodificarDatos(data) {
  try {
    const [documentHash, action, email, subject, sigHash] =
      AbiCoder.defaultAbiCoder().decode(TIPOS, data);
    return { ok: true, documentHash, action, email, subject: getAddress(subject), sigHash };
  } catch (e) {
    return { ok: false, error: e?.message ?? String(e) };
  }
}

export async function leerSchema(prov, cadena, uid) {
  const reg = new Contract(cadena.registry, ABI_REGISTRY, prov);
  const s = await reg.getSchema(uid);
  if (s.uid === `0x${"00".repeat(32)}`) return null;
  return { uid: s.uid, resolver: s.resolver, revocable: s.revocable, schema: s.schema };
}

export async function leerRecibo(prov, hash) {
  const r = await prov.getTransactionReceipt(hash);
  if (!r) return null;
  return { hash: r.hash, status: r.status, to: r.to, blockNumber: r.blockNumber };
}

// Normaliza una dirección para comparar. Devuelve null si no es una dirección.
export function dir(a) {
  try {
    return getAddress(String(a));
  } catch {
    return null;
  }
}
