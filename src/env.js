// Lectura del `.env`, sin dependencias.
//
// Es a propósito: este verificador tiene que poder correrse dentro de diez años
// sobre un zip que alguien encontró en un cajón, y cada paquete que agrega es un
// paquete que para entonces puede no instalarse. `dotenv` haría exactamente
// esto y nada más.
//
// Precedencia: lo que ya está en `process.env` gana siempre — así una variable
// pasada por línea de comandos (`RPC_URL=... node src/cli.js ...`) pisa al
// archivo sin que haya que editarlo.

import { readFileSync, existsSync } from "node:fs";

function parsear(texto) {
  const salida = {};
  for (const linea of texto.split(/\r?\n/)) {
    const l = linea.trim();
    if (!l || l.startsWith("#")) continue;
    const corte = l.indexOf("=");
    if (corte === -1) continue;
    const clave = l.slice(0, corte).trim().replace(/^export\s+/, "");
    let valor = l.slice(corte + 1).trim();
    // Un comentario al final de la línea, pero solo si el valor no está entre
    // comillas: una URL con `#` adentro es rara pero legal.
    if (!/^["']/.test(valor)) valor = valor.replace(/\s+#.*$/, "").trim();
    if (
      (valor.startsWith('"') && valor.endsWith('"')) ||
      (valor.startsWith("'") && valor.endsWith("'"))
    ) {
      valor = valor.slice(1, -1);
    }
    if (clave) salida[clave] = valor;
  }
  return salida;
}

// Carga el primer archivo que exista de la lista, sin pisar lo que ya esté
// definido en el entorno. Devuelve la ruta usada, o null.
export function cargarEnv(rutas) {
  for (const ruta of rutas) {
    if (!ruta || !existsSync(ruta)) continue;
    const valores = parsear(readFileSync(ruta, "utf8"));
    for (const [k, v] of Object.entries(valores)) {
      if (process.env[k] === undefined || process.env[k] === "") process.env[k] = v;
    }
    return ruta;
  }
  return null;
}

// Una variable, normalizada: vacía es lo mismo que ausente.
export function env(nombre) {
  const v = process.env[nombre];
  return v && v.trim() !== "" ? v.trim() : undefined;
}

export function envBool(nombre, porDefecto = false) {
  const v = env(nombre);
  if (v === undefined) return porDefecto;
  return /^(1|true|si|sí|yes|on)$/i.test(v);
}

export function envNum(nombre, porDefecto) {
  const v = env(nombre);
  if (v === undefined) return porDefecto;
  const n = Number(v);
  return Number.isFinite(n) ? n : porDefecto;
}
