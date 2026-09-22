// Un nodo JSON-RPC mínimo, para ejercitar el camino de red del verificador sin
// depender de que exista una atestación real en una red real.
//
// Contesta lo justo: el chainId, `getAttestation`, `getSchema` y el recibo de
// una transacción. Todo lo demás vuelve como error, que es lo que corresponde:
// si el verificador empieza a pedir cosas que no están acá, queremos enterarnos.

import { createServer } from "node:http";
import { AbiCoder, Interface, keccak256, toUtf8Bytes } from "ethers";

const ABI = new Interface([
  "function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
  "function getSchema(bytes32 uid) view returns (tuple(bytes32 uid, address resolver, bool revocable, string schema))",
]);

export const CERO32 = `0x${"00".repeat(32)}`;
export const CERO_ADDR = "0x0000000000000000000000000000000000000000";

// Los datos de una atestación, con el schema de sygners.
export function datosSygners({ documentHash, action, email, subject, sigHash = CERO32 }) {
  return AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "string", "string", "address", "bytes32"],
    [documentHash, action, email, subject, sigHash],
  );
}

export function atestacion(a) {
  return {
    uid: a.uid,
    schema: a.schema,
    time: BigInt(a.time ?? 0),
    expirationTime: BigInt(a.expirationTime ?? 0),
    revocationTime: BigInt(a.revocationTime ?? 0),
    refUID: a.refUID ?? CERO32,
    recipient: a.recipient ?? CERO_ADDR,
    attester: a.attester ?? CERO_ADDR,
    revocable: a.revocable ?? true,
    data: a.data,
  };
}

// estado = { chainId, atestaciones: {uid: atestacion}, schemas: {uid: texto}, recibos: {hash: {to}} }
export async function levantarNodo(estado) {
  const server = createServer((req, res) => {
    let cuerpo = "";
    req.on("data", (c) => (cuerpo += c));
    req.on("end", () => {
      let pedidos;
      try {
        pedidos = JSON.parse(cuerpo);
      } catch {
        res.writeHead(400).end();
        return;
      }
      const uno = !Array.isArray(pedidos);
      const lista = uno ? [pedidos] : pedidos;
      const respuestas = lista.map((p) => ({ jsonrpc: "2.0", id: p.id, ...responder(estado, p) }));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(uno ? respuestas[0] : respuestas));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, cerrar: () => new Promise((r) => server.close(r)) };
}

function responder(estado, p) {
  switch (p.method) {
    case "eth_chainId":
      return { result: `0x${estado.chainId.toString(16)}` };
    case "net_version":
      return { result: String(estado.chainId) };
    case "eth_blockNumber":
      return { result: "0x1234" };
    case "eth_call": {
      const datos = p.params[0].data;
      const frag = ABI.getFunction(datos.slice(0, 10));
      if (!frag) return { error: { code: -32601, message: `selector desconocido ${datos.slice(0, 10)}` } };
      const [uid] = ABI.decodeFunctionData(frag, datos);
      if (frag.name === "getAttestation") {
        const a = estado.atestaciones[uid.toLowerCase()];
        const vacia = atestacion({ uid: CERO32, schema: CERO32, data: "0x" });
        return { result: ABI.encodeFunctionResult(frag, [Object.values(a ?? vacia)]) };
      }
      const texto = estado.schemas[uid.toLowerCase()];
      const s = texto
        ? [uid, CERO_ADDR, true, texto]
        : [CERO32, CERO_ADDR, false, ""];
      return { result: ABI.encodeFunctionResult(frag, [s]) };
    }
    case "eth_getTransactionReceipt": {
      const hash = String(p.params[0]).toLowerCase();
      const r = estado.recibos[hash];
      if (!r) return { result: null };
      return {
        result: {
          transactionHash: hash,
          transactionIndex: "0x1",
          blockHash: keccak256(toUtf8Bytes(hash)),
          blockNumber: "0x1000",
          from: r.from ?? CERO_ADDR,
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
      return { error: { code: -32601, message: `método no soportado por el nodo falso: ${p.method}` } };
  }
}
