// A minimal JSON-RPC node, to exercise the verifier's network path without
// depending on a real attestation existing on a real network.
//
// It answers just enough: the chain id, `getAttestation`, `getSchema` and a
// transaction receipt. Everything else comes back as an error, which is the
// right behaviour: if the verifier starts asking for things that are not here,
// we want to know.

import { createServer } from "node:http";
import { AbiCoder, Interface, keccak256, toUtf8Bytes } from "ethers";

const ABI = new Interface([
  "function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
  "function getSchema(bytes32 uid) view returns (tuple(bytes32 uid, address resolver, bool revocable, string schema))",
]);

export const ZERO32 = `0x${"00".repeat(32)}`;
export const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

// An attestation's payload, with sygners' schema.
export function sygnersData({ documentHash, action, email, subject, sigHash = ZERO32 }) {
  return AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "string", "string", "address", "bytes32"],
    [documentHash, action, email, subject, sigHash],
  );
}

export function attestation(a) {
  return {
    uid: a.uid,
    schema: a.schema,
    time: BigInt(a.time ?? 0),
    expirationTime: BigInt(a.expirationTime ?? 0),
    revocationTime: BigInt(a.revocationTime ?? 0),
    refUID: a.refUID ?? ZERO32,
    recipient: a.recipient ?? ZERO_ADDR,
    attester: a.attester ?? ZERO_ADDR,
    revocable: a.revocable ?? true,
    data: a.data,
  };
}

// state = { chainId, attestations: {uid: attestation}, schemas: {uid: text}, receipts: {hash: {to}} }
export async function startNode(state) {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let requests;
      try {
        requests = JSON.parse(body);
      } catch {
        res.writeHead(400).end();
        return;
      }
      const single = !Array.isArray(requests);
      const list = single ? [requests] : requests;
      const answers = list.map((p) => ({ jsonrpc: "2.0", id: p.id, ...answer(state, p) }));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(single ? answers[0] : answers));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

function answer(state, p) {
  switch (p.method) {
    case "eth_chainId":
      return { result: `0x${state.chainId.toString(16)}` };
    case "net_version":
      return { result: String(state.chainId) };
    case "eth_blockNumber":
      return { result: "0x1234" };
    case "eth_call": {
      const data = p.params[0].data;
      const frag = ABI.getFunction(data.slice(0, 10));
      if (!frag) return { error: { code: -32601, message: `unknown selector ${data.slice(0, 10)}` } };
      const [uid] = ABI.decodeFunctionData(frag, data);
      if (frag.name === "getAttestation") {
        const a = state.attestations[uid.toLowerCase()];
        const empty = attestation({ uid: ZERO32, schema: ZERO32, data: "0x" });
        return { result: ABI.encodeFunctionResult(frag, [Object.values(a ?? empty)]) };
      }
      const text = state.schemas[uid.toLowerCase()];
      const s = text ? [uid, ZERO_ADDR, true, text] : [ZERO32, ZERO_ADDR, false, ""];
      return { result: ABI.encodeFunctionResult(frag, [s]) };
    }
    case "eth_getTransactionReceipt": {
      const hash = String(p.params[0]).toLowerCase();
      const r = state.receipts[hash];
      if (!r) return { result: null };
      return {
        result: {
          transactionHash: hash,
          transactionIndex: "0x1",
          blockHash: keccak256(toUtf8Bytes(hash)),
          blockNumber: "0x1000",
          from: r.from ?? ZERO_ADDR,
          to: r.to,
          cumulativeGasUsed: "0x1",
          gasUsed: "0x1",
          effectiveGasPrice: "0x1",
          contractAddress: null,
          logs: [],
          logsBloom: `0x${"00".repeat(256)}`,
          status: r.status ?? "0x1",
          type: "0x2",
        },
      };
    }
    default:
      return { error: { code: -32601, message: `method not supported by the fake node: ${p.method}` } };
  }
}
