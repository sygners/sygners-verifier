// El informe en pantalla.
//
// Lo lee alguien que tiene que decidir si un archivo prueba lo que dice
// probar, así que el orden es: veredicto arriba, los hechos de la operación
// después, y el detalle chequeo por chequeo al final. Las fallas se repiten al
// pie para que no haya que buscarlas entre los "ok".

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (cod, s) => (COLOR ? `\u001b[${cod}m${s}\u001b[0m` : s);
const verde = (s) => c("32", s);
const rojo = (s) => c("31", s);
const amarillo = (s) => c("33", s);
const gris = (s) => c("90", s);
const negrita = (s) => c("1", s);

const MARCA = { ok: verde("  ok  "), falla: rojo(" FALLA"), aviso: amarillo(" aviso"), omitido: gris("  —   "), info: gris("  ·   ") };

const TITULO_AREA = {
  archivo: "El paquete",
  manifiesto: "El manifiesto",
  documento: "El documento",
  cadena: "La cadena",
  firmas: "Las firmas",
};

const VEREDICTO = {
  VERIFICADO: {
    texto: "VERIFICA",
    pinta: verde,
    glosa: "El documento del paquete es el que se ancló, y las atestaciones están en la cadena y dicen lo que el manifiesto dice que dicen.",
  },
  PARCIAL: {
    texto: "VERIFICA PARCIALMENTE (sin cadena)",
    pinta: amarillo,
    glosa: "El paquete es internamente consistente: el documento coincide con el hash del manifiesto. NO se coteja contra la cadena, así que esto todavía no prueba cuándo existió ni quién lo ancló.",
    // Con el formato 2 el modo sin red deja de ser solo "consistente consigo
    // mismo": la firma se verifica de verdad, y el informe tiene que decirlo o
    // se lee como si hubiera probado menos de lo que probó.
    glosaConFirmas:
      "Las firmas se verificaron: la dirección recuperada de cada una es la que el manifiesto declara, y el documento coincide con el hash firmado. Lo único que falta es la cadena, que es la que fecha el anclaje y dice quién lo hizo.",
  },
  SIMULADO: {
    texto: "EVIDENCIA SIMULADA",
    pinta: rojo,
    glosa: "El paquete salió de una instancia de sygners SIN cadena configurada: sus identificadores on-chain son deterministas y no corresponden a ninguna atestación. No prueba nada frente a un tercero.",
  },
  NO_VERIFICA: {
    texto: "NO VERIFICA",
    pinta: rojo,
    glosa: "Al menos un chequeo bloqueante falló. El detalle está abajo.",
  },
};

export function imprimirInforme(r, { archivo }) {
  const v = VEREDICTO[r.veredicto];
  const firmasProbadas = r.chequeos.some(
    (c) => /^firma\.\d+\.recuperada$/.test(c.id) && c.estado === "ok",
  );
  const glosa = (firmasProbadas && v.glosaConFirmas) || v.glosa;
  const L = [];
  L.push("");
  L.push(negrita("ARCHIVO DE EVIDENCIA — verificación independiente"));
  L.push(gris(archivo));
  L.push("");
  L.push(`  ${v.pinta(negrita(v.texto))}`);
  L.push(`  ${gris(glosa)}`);
  L.push("");

  const op = r.operacion;
  if (op) {
    L.push(negrita("La operación"));
    const campo = (k, val) => L.push(`  ${k.padEnd(18)} ${val ?? gris("—")}`);
    campo("Operación", op.titulo);
    campo("Id", op.documentoId);
    campo("Documento", op.archivo);
    campo("SHA-256", op.hashCalculado ?? op.hashDeclarado);
    campo("Red", op.chainId ? `${op.red} (chainId ${op.chainId})` : null);
    campo("Registro", op.registroUid);
    if (op.registroUrl) L.push(`  ${"".padEnd(18)} ${gris(op.registroUrl)}`);
    campo("Emisor", op.emisor ? `${op.emisor.email} · ${op.emisor.wallet}` : null);
    campo("Creado", op.fechas?.creado);
    campo("Última firma", op.fechas?.ultimaFirma);
    campo("Vence (copia)", op.fechas?.vence);
    campo("Manifiesto del", op.generadoEl);
    L.push("");
    L.push(negrita(`Firmantes (${op.firmantes.length})`));
    for (const f of op.firmantes) {
      L.push(`  · ${f.email}${f.wallet ? ` — ${f.wallet}` : ""}`);
      L.push(`    ${gris(`${f.estado}${f.firmadoEl ? ` · ${f.firmadoEl}` : ""}${f.attestationUid ? ` · ${f.attestationUid}` : ""}`)}`);
    }
    L.push("");
  }

  L.push(negrita("Chequeos"));
  // Agrupados por área: los chequeos se producen intercalados (por cada
  // firmante se miran su firma y su atestación), y repetir los encabezados
  // hacía ilegible el informe justo donde hay más para leer.
  const orden = Object.keys(TITULO_AREA);
  const porArea = [...r.chequeos].sort(
    (a, b) => orden.indexOf(a.area) - orden.indexOf(b.area),
  );
  let areaActual = null;
  for (const ch of porArea) {
    if (ch.area !== areaActual) {
      areaActual = ch.area;
      L.push(`  ${gris(TITULO_AREA[areaActual] ?? areaActual)}`);
    }
    L.push(`  ${MARCA[ch.estado]}  ${ch.titulo}`);
    if (ch.detalle) L.push(`          ${gris(ch.detalle)}`);
  }
  L.push("");

  const fallas = r.chequeos.filter((x) => x.estado === "falla");
  if (fallas.length) {
    L.push(rojo(negrita(`Por qué no verifica (${fallas.length})`)));
    for (const f of fallas) L.push(`  ${rojo("·")} ${f.titulo}: ${f.detalle ?? ""}`);
    L.push("");
  }

  const { ok, avisos, omitidos } = r.resumen;
  L.push(
    gris(
      `${ok} ok · ${fallas.length} fallas · ${avisos} avisos · ${omitidos} omitidos`,
    ),
  );
  L.push("");
  process.stdout.write(L.join("\n"));
}

export function imprimirJson(r) {
  process.stdout.write(JSON.stringify(r, null, 2) + "\n");
}
