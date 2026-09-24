// Reading EAS over RPC: the attestations and the schema, as they are on chain,
// going through no sygners service and no easscan.
//
// Only `eth_call` and `eth_getTransactionReceipt` are used, which any public
// node serves: no archive node and no API key needed.

import { Contract, FetchRequest, JsonRpcProvider, AbiCoder, getAddress } from "ethers";

const EAS_ABI = [
  "function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
];

const REGISTRY_ABI = [
  "function getSchema(bytes32 uid) view returns (tuple(bytes32 uid, address resolver, bool revocable, string schema))",
];

// The types of sygners' schema, in order. It is what `SchemaEncoder` encodes
// and therefore what has to be decoded: plain ABI, nothing proprietary.
const TYPES = ["bytes32", "string", "string", "address", "bytes32"];

export function provider(chain, timeoutMs) {
  const req = new FetchRequest(chain.rpcUrl);
  req.timeout = timeoutMs;
  // No network pinned on purpose: we want to ASK the node for its chain id and
  // compare it with the manifest's, not take it for granted.
  return new JsonRpcProvider(req, undefined, { polling: false, staticNetwork: false });
}

export async function nodeChainId(prov) {
  const net = await prov.getNetwork();
  return Number(net.chainId);
}

export async function readAttestation(prov, chain, uid) {
  const eas = new Contract(chain.eas, EAS_ABI, prov);
  const a = await eas.getAttestation(uid);
  const empty = a.schema === `0x${"00".repeat(32)}` && a.time === 0n;
  if (empty) return null;
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

// Decodes the attestation payload with sygners' schema. If the bytes do not
// match that schema it returns the error instead of throwing: that is a finding.
export function decodeData(data) {
  try {
    const [documentHash, action, email, subject, sigHash] =
      AbiCoder.defaultAbiCoder().decode(TYPES, data);
    return { ok: true, documentHash, action, email, subject: getAddress(subject), sigHash };
  } catch (e) {
    return { ok: false, error: e?.message ?? String(e) };
  }
}

export async function readSchema(prov, chain, uid) {
  const reg = new Contract(chain.registry, REGISTRY_ABI, prov);
  const s = await reg.getSchema(uid);
  if (s.uid === `0x${"00".repeat(32)}`) return null;
  return { uid: s.uid, resolver: s.resolver, revocable: s.revocable, schema: s.schema };
}

export async function readReceipt(prov, hash) {
  const r = await prov.getTransactionReceipt(hash);
  if (!r) return null;
  return { hash: r.hash, status: r.status, to: r.to, blockNumber: r.blockNumber };
}

// Normalizes an address for comparison. Returns null if it is not an address.
export function addr(a) {
  try {
    return getAddress(String(a));
  } catch {
    return null;
  }
}
