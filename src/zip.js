// Apertura del .zip de evidencia.
//
// Reimplementa `leerArchivoDeEvidencia` de sygners con una diferencia que es
// todo el punto de este programa: acá NADA tira excepción por estar incompleto.
// Un zip al que le falta el manifiesto no es un error del verificador, es un
// hallazgo del verificador — y tiene que llegar al informe como tal, junto con
// el resto de los chequeos.

import { unzipSync, strFromU8 } from "fflate";

export const NOMBRE_CONSTANCIA = "constancia.pdf";
export const NOMBRE_MANIFIESTO = "manifiesto.json";
export const NOMBRE_LEEME = "LEEME.txt";

export function abrirEvidencia(bytes) {
  let contenido;
  try {
    contenido = unzipSync(new Uint8Array(bytes));
  } catch (e) {
    return { ok: false, error: `No se pudo abrir el .zip: ${e?.message ?? e}` };
  }

  const archivos = Object.keys(contenido);
  const conocidos = new Set([NOMBRE_CONSTANCIA, NOMBRE_MANIFIESTO, NOMBRE_LEEME]);
  // Cualquier entrada que no sea una de las tres fijas es "el documento".
  // Directorios y archivos de basura de macOS (`__MACOSX/`, `.DS_Store`) no
  // cuentan: un zip reempaquetado a mano los trae y no son el documento.
  const candidatos = archivos.filter(
    (n) =>
      !conocidos.has(n) &&
      !n.endsWith("/") &&
      !n.startsWith("__MACOSX/") &&
      !n.split("/").pop().startsWith("."),
  );

  let manifiesto = null;
  let errorManifiesto = null;
  if (contenido[NOMBRE_MANIFIESTO]) {
    try {
      manifiesto = JSON.parse(strFromU8(contenido[NOMBRE_MANIFIESTO]));
    } catch (e) {
      errorManifiesto = `El manifiesto no es JSON válido: ${e?.message ?? e}`;
    }
  } else {
    errorManifiesto = `El .zip no trae ${NOMBRE_MANIFIESTO}.`;
  }

  return {
    ok: true,
    archivos,
    candidatosDocumento: candidatos,
    nombreDocumento: candidatos.length === 1 ? candidatos[0] : null,
    documento: candidatos.length === 1 ? contenido[candidatos[0]] : null,
    pdf: contenido[NOMBRE_CONSTANCIA] ?? null,
    leeme: contenido[NOMBRE_LEEME] ? strFromU8(contenido[NOMBRE_LEEME]) : null,
    manifiestoCrudo: contenido[NOMBRE_MANIFIESTO] ?? null,
    manifiesto,
    errorManifiesto,
  };
}
