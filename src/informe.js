// El informe: texto estructurado, pensado para leerse entero y para pegarse en
// otro lado sin perder nada.
//
// Está organizado por SUJETO y no por tipo de chequeo: el paquete, el
// documento, el anclaje, y después un bloque por firmante con absolutamente
// todo lo suyo junto —lo que dice el manifiesto, lo que dice su firma y lo que
// dice la cadena—. La versión anterior agrupaba por dónde se había hecho cada
// comprobación, que es cómo las produce el verificador y no cómo las necesita
// leer alguien que tiene que decidir si una firma vale.
//
// Cada línea de chequeo lleva su estado y, debajo, el dato con el que se
// resolvió: quien lee tiene que poder rehacer la cuenta, no confiar en el
// veredicto.

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (cod, s) => (COLOR ? `\u001b[${cod}m${s}\u001b[0m` : s);
const verde = (s) => c("32", s);
const rojo = (s) => c("31", s);
const amarillo = (s) => c("33", s);
const gris = (s) => c("90", s);
const negrita = (s) => c("1", s);

const MARCA = {
  ok: verde("[ ok ]"),
  falla: rojo("[FALLA]"),
  aviso: amarillo("[aviso]"),
  omitido: gris("[  -  ]"),
  info: gris("[  ·  ]"),
};

const VEREDICTO = {
  VERIFICADO: {
    texto: "VERIFICA",
    pinta: verde,
    glosa:
      "El documento del paquete es el que se ancló, y las atestaciones están en la cadena y dicen lo que el manifiesto dice que dicen.",
  },
  PARCIAL: {
    texto: "VERIFICA PARCIALMENTE (sin cadena)",
    pinta: amarillo,
    glosa:
      "El paquete es internamente consistente: el documento coincide con el hash del manifiesto. NO se coteja contra la cadena, así que esto todavía no prueba cuándo existió ni quién lo ancló.",
    glosaConFirmas:
      "Las firmas se verificaron: la dirección recuperada de cada una es la que el manifiesto declara, y el documento coincide con el hash firmado. Lo único que falta es la cadena, que es la que fecha el anclaje y dice quién lo hizo.",
  },
  SIMULADO: {
    texto: "EVIDENCIA SIMULADA",
    pinta: rojo,
    glosa:
      "El paquete salió de una instancia de sygners SIN cadena configurada: sus identificadores on-chain son deterministas y no corresponden a ninguna atestación. No prueba nada frente a un tercero.",
  },
  NO_VERIFICA: {
    texto: "NO VERIFICA",
    pinta: rojo,
    glosa: "Al menos un chequeo bloqueante falló.",
  },
};

const ANCHO = 74;
const REGLA = "─".repeat(ANCHO);
const REGLA_DOBLE = "═".repeat(ANCHO);

// ── Armado ───────────────────────────────────────────────────────────────────

// A qué sujeto pertenece cada chequeo. El id manda: `firma.3.loQueSea` es del
// cuarto firmante, sin importar si la comprobación se hizo contra su firma o
// contra la cadena.
function repartir(chequeos) {
  const s = { paquete: [], documento: [], anclaje: [], esquema: [], claves: [], firmantes: new Map() };
  for (const ch of chequeos) {
    const porFirmante = /^firma\.(\d+)\./.exec(ch.id);
    if (porFirmante) {
      const i = Number(porFirmante[1]);
      if (!s.firmantes.has(i)) s.firmantes.set(i, []);
      s.firmantes.get(i).push(ch);
      continue;
    }
    if (ch.area === "claves") s.claves.push(ch);
    else if (ch.id.startsWith("firma.")) s.esquema.push(ch);
    else if (ch.area === "documento") s.documento.push(ch);
    else if (ch.area === "cadena" || ch.id.startsWith("registro.") || ch.id.startsWith("schema."))
      s.anclaje.push(ch);
    else s.paquete.push(ch);
  }
  return s;
}

export function imprimirInforme(r, { archivo }) {
  const L = [];
  const op = r.operacion;
  const sec = repartir(r.chequeos);

  const campo = (k, v) => {
    if (v === null || v === undefined || v === "") return;
    L.push(` ${k.padEnd(13)}${v}`);
  };
  const titulo = (texto) => {
    L.push("");
    L.push(gris(REGLA));
    L.push(` ${negrita(texto)}`);
    L.push(gris(REGLA));
  };
  // Un chequeo: su estado, su enunciado y el dato con el que se resolvió.
  const linea = (ch, quitarPrefijo) => {
    let t = ch.titulo;
    if (quitarPrefijo && t.startsWith(`${quitarPrefijo}: `)) t = t.slice(quitarPrefijo.length + 2);
    L.push(` ${MARCA[ch.estado]} ${t}`);
    if (ch.detalle) {
      for (const parte of envolver(ch.detalle, ANCHO - 10)) L.push(`        ${gris(parte)}`);
    }
  };
  const bloque = (chequeos, quitarPrefijo) => {
    if (chequeos.length === 0) return;
    L.push("");
    for (const ch of chequeos) linea(ch, quitarPrefijo);
  };

  // ── Encabezado ──
  const v = VEREDICTO[r.veredicto];
  const firmasProbadas = r.chequeos.some(
    (x) => /^firma\.\d+\.recuperada$/.test(x.id) && x.estado === "ok",
  );
  const glosa = (firmasProbadas && v.glosaConFirmas) || v.glosa;

  L.push("");
  L.push(gris(REGLA_DOBLE));
  L.push(` ${negrita("VERIFICACIÓN DE ARCHIVO DE EVIDENCIA")} ${gris("· sygners · sin la plataforma")}`);
  L.push(gris(REGLA_DOBLE));
  campo("Archivo", archivo);
  campo("Verificado", new Date().toISOString());
  campo("Veredicto", v.pinta(negrita(v.texto)));
  for (const parte of envolver(glosa, ANCHO - 14)) L.push(` ${"".padEnd(13)}${gris(parte)}`);
  campo(
    "Chequeos",
    `${r.resumen.ok} ok · ${r.resumen.fallas} fallas · ${r.resumen.avisos} avisos · ${r.resumen.omitidos} omitidos`,
  );

  // ── 1. Paquete ──
  titulo("1. PAQUETE");
  campo("Formato", op ? `manifiesto formato ${op.formato ?? "?"}` : null);
  campo("Generado", op?.generadoEl);
  bloque(sec.paquete);

  // ── 2. Documento ──
  titulo("2. DOCUMENTO");
  campo("Operación", op?.titulo);
  campo("Id", op?.documentoId);
  campo("Archivo", op?.archivo);
  campo("Tamaño", op?.tamano != null ? `${op.tamano} bytes` : null);
  campo("SHA-256", op?.hashCalculado ?? op?.hashDeclarado);
  campo("Emisor", op?.emisor ? `${op.emisor.email} · ${op.emisor.wallet}` : null);
  campo("Creado", op?.fechas?.creado);
  campo("Última firma", op?.fechas?.ultimaFirma);
  campo("Vence copia", op?.fechas?.vence);
  bloque(sec.documento);

  // ── 3. Anclaje ──
  titulo("3. ANCLAJE EN LA CADENA");
  campo("Red", op?.chainId ? `${op.red} (chainId ${op.chainId})` : null);
  campo("Registro", op?.registroUid);
  campo("Explorador", op?.registroUrl);
  campo("Atestador", op?.atestador);
  campo("Schema", op?.schemaUid);
  bloque(sec.anclaje);

  // ── 4. Esquema de firma ──
  if (sec.esquema.length) {
    titulo("4. ESQUEMA DE FIRMA (EIP-712)");
    bloque(sec.esquema);
  }
  let n = sec.esquema.length ? 5 : 4;

  // ── 5+. Un bloque por firmante ──
  const firmantes = op?.firmantes ?? [];
  const total = firmantes.length;
  for (const [i, f] of firmantes.entries()) {
    titulo(`${n++}. FIRMANTE ${i + 1} DE ${total} — ${f.email ?? "(sin correo)"}`);
    campo("Wallet", f.wallet);
    campo("Estado", f.estado);
    campo("Firmó el", f.firmadoEl);
    campo("Atestación", f.attestationUid);
    campo("Explorador", f.url);
    campo("Transacción", f.txHash);
    campo("Huella firma", f.sigHash);
    campo("Firma cruda", f.firma ? `${f.firma.slice(0, 20)}… (${(f.firma.length - 2) / 2} bytes)` : gris("no incluida en el paquete"));
    bloque(sec.firmantes.get(i) ?? [], f.email);
  }
  // Chequeos de firmantes que el manifiesto no llegó a listar.
  for (const [i, chequeos] of sec.firmantes) {
    if (i < total) continue;
    titulo(`${n++}. FIRMANTE ${i + 1}`);
    bloque(chequeos);
  }

  // ── Claves ──
  if (sec.claves.length) {
    const aportadas = sec.claves.some((x) => x.id.startsWith("clave."));
    titulo(`${n++}. CLAVES PRIVADAS DE LOS FIRMANTES`);
    if (aportadas) L.push(gris(" Acreditan control de la wallet, no identidad."));
    bloque(sec.claves);
  }

  // ── Resultado ──
  titulo("RESULTADO");
  L.push(` ${v.pinta(negrita(v.texto))}`);
  const fallas = r.chequeos.filter((x) => x.estado === "falla");
  const avisos = r.chequeos.filter((x) => x.estado === "aviso");
  if (fallas.length) {
    L.push("");
    L.push(` ${rojo(negrita(`Fallas (${fallas.length})`))}`);
    for (const f of fallas) {
      L.push(` ${rojo("·")} ${f.titulo}`);
      if (f.detalle) for (const p of envolver(f.detalle, ANCHO - 4)) L.push(`   ${gris(p)}`);
    }
  }
  if (avisos.length) {
    L.push("");
    L.push(` ${amarillo(negrita(`Avisos (${avisos.length})`))}`);
    for (const a of avisos) L.push(` ${amarillo("·")} ${a.titulo}`);
  }
  L.push("");
  process.stdout.write(L.join("\n") + "\n");
}

// Corta un texto en líneas de a lo sumo `ancho`, sin partir palabras.
function envolver(texto, ancho) {
  const salida = [];
  for (const parrafo of String(texto).split("\n")) {
    let linea = "";
    for (const palabra of parrafo.split(/\s+/)) {
      if (linea && (linea + " " + palabra).length > ancho) {
        salida.push(linea);
        linea = palabra;
      } else {
        linea = linea ? `${linea} ${palabra}` : palabra;
      }
    }
    salida.push(linea);
  }
  return salida;
}
