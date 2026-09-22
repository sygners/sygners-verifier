#!/usr/bin/env node
// sygners-verificar — verifica un archivo de evidencia .zip sin sygners.
//
// Fuentes de verdad: el zip que te pasaron y un nodo RPC de la cadena que el
// propio manifiesto declara. Nada más. No hay ninguna llamada a la plataforma
// en ninguna parte de este programa, y esa es toda su razón de existir: una
// evidencia que dependa de que su emisor siga vivo para poder comprobarse no
// es evidencia.
//
// Salidas: 0 verifica · 1 no verifica (o simulada) · 2 error de uso.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cargarEnv } from "./env.js";
import { opciones } from "./config.js";
import { verificarEvidencia } from "./verificar.js";
import { imprimirInforme, imprimirJson } from "./informe.js";
import { abrirEvidencia } from "./zip.js";

const AQUI = dirname(fileURLToPath(import.meta.url));

const AYUDA = `
sygners-verificar <archivo.zip> [opciones]

  Verifica un archivo de evidencia de sygners contra sí mismo y contra la cadena
  donde dice estar anclado. No consulta a sygners.

Opciones
  --sin-cadena          Solo chequeos offline (estructura + hash). Veredicto parcial.
  --json                Informe en JSON por stdout (para automatizar).
  --extraer <carpeta>   Además, escribe el documento, la constancia y el manifiesto.
  --rpc <url>           RPC a usar, por encima de las variables de entorno.
  --schema-uid <0x…>    UID de schema EAS exigido.
  --attester <0x…>      Dirección que tuvo que anclar las atestaciones.
  --sin-tx              No pide los recibos de transacción (menos pedidos al RPC).
  --estricto            Los avisos también hacen fallar.
  --tolerancia <seg>    Diferencia admitida entre la fecha declarada y la del bloque.
  --env <archivo>       Archivo .env a usar (por defecto ./.env y el del verificador).
  -h, --help            Esto.

Variables de entorno: ver .env.example (RPC_URL_<chainId>, EAS_CONTRACT_ADDRESS_<chainId>,
EAS_SCHEMA_UID, SYGNERS_ATTESTER, SIN_CADENA, VERIFICAR_TX, ESTRICTO, …).
`;

function parsearArgs(argv) {
  const f = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const sig = () => argv[++i];
    switch (a) {
      case "-h": case "--help": f.ayuda = true; break;
      case "--json": f.json = true; break;
      case "--sin-cadena": f.sinCadena = true; break;
      case "--sin-tx": f.verificarTx = false; break;
      case "--estricto": f.estricto = true; break;
      case "--extraer": f.extraer = sig(); break;
      case "--rpc": f.rpc = sig(); break;
      case "--schema-uid": f.schemaUid = sig(); break;
      case "--attester": f.attester = sig(); break;
      case "--tolerancia": f.toleranciaSegundos = Number(sig()); break;
      case "--env": f.env = sig(); break;
      default:
        if (a.startsWith("-")) { f.desconocida = a; }
        else f._.push(a);
    }
  }
  return f;
}

async function main() {
  const f = parsearArgs(process.argv.slice(2));
  if (f.ayuda || f._.length === 0) {
    process.stdout.write(AYUDA);
    process.exit(f.ayuda ? 0 : 2);
  }
  if (f.desconocida) {
    process.stderr.write(`Opción desconocida: ${f.desconocida}\n${AYUDA}`);
    process.exit(2);
  }

  // El .env: el del directorio donde se corre, y si no el que vive al lado del
  // verificador. Lo que ya esté en el entorno gana.
  cargarEnv([f.env, resolve(process.cwd(), ".env"), join(AQUI, "..", ".env")].filter(Boolean));

  const ruta = resolve(f._[0]);
  if (!existsSync(ruta)) {
    process.stderr.write(`No existe el archivo: ${ruta}\n`);
    process.exit(2);
  }

  const bytes = readFileSync(ruta);
  const opts = opciones(f);
  const r = await verificarEvidencia(bytes, opts);

  if (f.extraer) {
    const zip = abrirEvidencia(bytes);
    if (zip.ok) {
      mkdirSync(f.extraer, { recursive: true });
      const escribir = (n, b) => b && writeFileSync(join(f.extraer, basename(n)), Buffer.from(b));
      escribir(zip.nombreDocumento ?? "documento.bin", zip.documento);
      escribir("constancia.pdf", zip.pdf);
      escribir("manifiesto.json", zip.manifiestoCrudo);
      if (zip.leeme) writeFileSync(join(f.extraer, "LEEME.txt"), zip.leeme);
      if (!f.json) process.stderr.write(`Contenido extraído en ${resolve(f.extraer)}\n`);
    }
  }

  if (f.json) imprimirJson({ ...r, archivo: ruta });
  else imprimirInforme(r, { archivo: ruta });

  process.exit(r.veredicto === "VERIFICADO" || r.veredicto === "PARCIAL" ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`Error inesperado del verificador: ${e?.stack ?? e}\n`);
  process.exit(2);
});
