#!/usr/bin/env node
// sygners-verificar — verifica un archivo de evidencia .zip sin sygners.
//
// Un solo argumento: el zip. Todo lo demás sale del `.env` (ver `.env.example`).
// No hay opciones que cambien el resultado a propósito: un verificador cuyo
// veredicto depende de cómo lo invocaste no sirve para mostrárselo a nadie.
//
// Salidas: 0 verifica · 1 no verifica (o simulada) · 2 error de uso.

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cargarEnv } from "./env.js";
import { opciones } from "./config.js";
import { verificarEvidencia } from "./verificar.js";
import { imprimirInforme } from "./informe.js";

const AQUI = dirname(fileURLToPath(import.meta.url));

const AYUDA = `
sygners-verificar <archivo.zip>

  Verifica un archivo de evidencia de sygners contra sí mismo y contra la cadena
  donde dice estar anclado. No consulta a sygners.

  La configuración vive en el .env (RPC por cadena, schema y atestador
  esperados, claves de firmantes, SIN_CADENA). Ver .env.example.
`;

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] === "-h" || args[0] === "--help") {
    process.stdout.write(AYUDA);
    process.exit(args[0] === "-h" || args[0] === "--help" ? 0 : 2);
  }

  // El .env del directorio donde se corre, y si no el que vive al lado del
  // verificador. Lo que ya esté en el entorno gana.
  cargarEnv([resolve(process.cwd(), ".env"), join(AQUI, "..", ".env")]);

  const ruta = resolve(args[0]);
  if (!existsSync(ruta)) {
    process.stderr.write(`No existe el archivo: ${ruta}\n`);
    process.exit(2);
  }

  const r = await verificarEvidencia(readFileSync(ruta), opciones());
  imprimirInforme(r, { archivo: ruta });
  process.exit(r.veredicto === "VERIFICADO" || r.veredicto === "PARCIAL" ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`Error inesperado del verificador: ${e?.stack ?? e}\n`);
  process.exit(2);
});
