// Detección de evidencia SIMULADA (el "modo dev" de sygners).
//
// Cuando a la plataforma le falta el relayer, el RPC o el UID del schema, no
// ancla nada: `src/lib/eas.ts` devuelve UIDs y tx hashes deterministas
// —`keccak256("uid:" + semilla)`— para que el flujo local siga siendo
// trazable. Son evidencia de nada.
//
// Un zip así es indistinguible de uno real a simple vista: trae sus UIDs de 32
// bytes y sus enlaces al explorador. La diferencia es que los UIDs se pueden
// RECALCULAR sin consultar nada, y eso es exactamente lo que hacemos acá.
//
// ⚠️ Esto no es un chequeo redundante con "la atestación no existe en la
// cadena". Los dos dan lo mismo mirando el resultado, pero dicen cosas
// distintas: "no existe" puede ser un RPC equivocado o una red equivocada;
// "coincide con el UID simulado" es una afirmación exacta sobre el origen del
// zip, y se puede hacer sin red.

import { keccak256, toUtf8Bytes } from "ethers";

const kdeSemilla = (prefijo, semilla) => keccak256(toUtf8Bytes(`${prefijo}:${semilla}`));

export function uidSimuladoDeRegistro(documentId) {
  return kdeSemilla("uid", `register:${documentId}`);
}
export function txSimuladoDeRegistro(documentId) {
  return kdeSemilla("tx", `register:${documentId}`);
}
// La semilla de la firma incluye el hash de la firma, que el manifiesto no
// lleva: solo se puede recalcular si se lo conoce por otro lado. Queda
// disponible por completitud; el veredicto de "simulado" lo decide el registro.
export function uidSimuladoDeFirma(wallet, sigHash) {
  return kdeSemilla("uid", `sign:${wallet}:${sigHash}`);
}

const igual = (a, b) => Boolean(a && b && a.toLowerCase() === b.toLowerCase());

// ¿El manifiesto describe una operación anclada en modo simulado?
export function detectarSimulado(manifiesto) {
  const id = manifiesto?.documento?.id;
  if (!id) return { simulado: false, motivos: [] };
  const motivos = [];
  if (igual(manifiesto?.cadena?.registroUid, uidSimuladoDeRegistro(id))) {
    motivos.push("el UID del registro es el que produce el modo simulado para este documento");
  }
  if (igual(manifiesto?.cadena?.registroTxHash, txSimuladoDeRegistro(id))) {
    motivos.push("el hash de transacción del registro es el del modo simulado");
  }
  return { simulado: motivos.length > 0, motivos };
}
