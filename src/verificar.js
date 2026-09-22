// El verificador: toma los bytes de un .zip y devuelve una lista de chequeos y
// un veredicto.
//
// Tres reglas de diseño, y las tres son deliberadas:
//
//  1. **Nada tira excepción por un hallazgo.** Un zip roto, un manifiesto sin
//     campos o una atestación inexistente son RESULTADOS, y el informe los
//     muestra junto a todo lo demás. Solo un error de programa interrumpe.
//  2. **Se corre todo lo que se pueda.** Que falle el hash no cancela los
//     chequeos de cadena: quien verifica quiere el cuadro completo, no el
//     primer problema.
//  3. **Nada se pregunta a sygners.** Las únicas fuentes son el zip y un nodo
//     RPC de la cadena que el propio manifiesto declara.

import { sha256Hex, hashesIguales } from "./hash.js";
import {
  DECLARACION,
  compararEip712,
  esFirmaBienFormada,
  huella,
  mismaDireccion,
  recuperarFirmante,
} from "./firma.js";
import { abrirEvidencia, NOMBRE_CONSTANCIA, NOMBRE_LEEME, NOMBRE_MANIFIESTO } from "./zip.js";
import { detectarSimulado } from "./simulado.js";
import {
  ACCION_FIRMA,
  ACCION_REGISTRO,
  BYTES32_CERO,
  SCHEMA_DEFINICION,
  cadenaDe,
  expectativas,
} from "./config.js";
import {
  chainIdDelNodo,
  decodificarDatos,
  dir,
  leerAtestacion,
  leerRecibo,
  leerSchema,
  proveedor,
} from "./eas.js";

// Formato 1: el original. Formato 2 (22/09/2026): agrega `eip712` y, por
// firmante, `mensaje` + `firma` + `sigHash` — la firma cruda, que es lo que
// permite recuperar la dirección sin creerle a nadie.
const FORMATO_MAXIMO = 2;
const FORMATO_CON_FIRMA_CRUDA = 2;

class Chequeos {
  constructor() {
    this.lista = [];
  }
  agregar(area, id, titulo, estado, detalle, extra = {}) {
    this.lista.push({ area, id, titulo, estado, detalle: detalle ?? null, ...extra });
    return estado;
  }
  ok(area, id, titulo, detalle, extra) {
    return this.agregar(area, id, titulo, "ok", detalle, extra);
  }
  falla(area, id, titulo, detalle, extra) {
    return this.agregar(area, id, titulo, "falla", detalle, extra);
  }
  aviso(area, id, titulo, detalle, extra) {
    return this.agregar(area, id, titulo, "aviso", detalle, extra);
  }
  omitido(area, id, titulo, detalle, extra) {
    return this.agregar(area, id, titulo, "omitido", detalle, extra);
  }
  info(area, id, titulo, detalle, extra) {
    return this.agregar(area, id, titulo, "info", detalle, extra);
  }
  // `condicion ? ok : falla`, que es la forma de casi todos los chequeos.
  segun(cond, area, id, titulo, detalleOk, detalleMal, extra) {
    return cond
      ? this.ok(area, id, titulo, detalleOk, extra)
      : this.falla(area, id, titulo, detalleMal, extra);
  }
  cuenta(estado) {
    return this.lista.filter((c) => c.estado === estado).length;
  }
}

const esHex32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
const fecha = (v) => {
  if (typeof v !== "string") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};
const seg = (d) => Math.floor(d.getTime() / 1000);

// ── 1. Estructura del paquete ────────────────────────────────────────────────
function chequearEstructura(c, zip) {
  const falta = [NOMBRE_MANIFIESTO, NOMBRE_CONSTANCIA, NOMBRE_LEEME].filter(
    (n) => !zip.archivos.includes(n),
  );
  c.segun(
    falta.length === 0,
    "archivo",
    "estructura.piezas",
    "El paquete trae las piezas que declara el formato",
    `${zip.archivos.length} entradas: ${zip.archivos.join(", ")}`,
    `Faltan: ${falta.join(", ")}`,
  );

  if (zip.candidatosDocumento.length === 1) {
    c.ok("archivo", "estructura.documento", "Hay exactamente un documento adentro", zip.nombreDocumento);
  } else if (zip.candidatosDocumento.length === 0) {
    c.falla("archivo", "estructura.documento", "Hay exactamente un documento adentro", "No hay ninguno.");
  } else {
    c.falla(
      "archivo",
      "estructura.documento",
      "Hay exactamente un documento adentro",
      `Hay ${zip.candidatosDocumento.length}: ${zip.candidatosDocumento.join(", ")}. No se puede saber cuál se firmó.`,
    );
  }

  if (zip.pdf) {
    const cabecera = Buffer.from(zip.pdf.slice(0, 5)).toString("latin1");
    c.segun(
      cabecera.startsWith("%PDF"),
      "archivo",
      "estructura.constancia",
      "La constancia es un PDF",
      `${zip.pdf.length} bytes`,
      `Empieza con ${JSON.stringify(cabecera)}, no con %PDF.`,
    );
  }
}

// ── 2. Forma del manifiesto ──────────────────────────────────────────────────
function chequearManifiesto(c, m) {
  const faltantes = [];
  const pedir = (ruta) => {
    const v = ruta.split(".").reduce((o, k) => (o == null ? undefined : o[k]), m);
    if (v === undefined || v === null || v === "") faltantes.push(ruta);
    return v;
  };
  for (const ruta of [
    "formato",
    "documento.id",
    "documento.titulo",
    "documento.nombreArchivo",
    "documento.hash",
    "cadena.chainId",
    "emisor.email",
    "emisor.wallet",
    "fechas.creado",
    "generadoEl",
  ]) {
    pedir(ruta);
  }
  if (!Array.isArray(m.firmantes)) faltantes.push("firmantes");

  c.segun(
    faltantes.length === 0,
    "manifiesto",
    "manifiesto.campos",
    "El manifiesto tiene todos los campos obligatorios",
    null,
    `Faltan: ${faltantes.join(", ")}`,
  );

  if (m.formato >= 1 && m.formato <= FORMATO_MAXIMO) {
    c.ok(
      "manifiesto",
      "manifiesto.formato",
      "Formato de manifiesto conocido",
      m.formato >= FORMATO_CON_FIRMA_CRUDA
        ? `formato ${m.formato} — trae la firma cruda de cada firmante`
        : `formato ${m.formato} — sin firma cruda (anterior al 22/09/2026)`,
    );
  } else if (typeof m.formato === "number" && m.formato > FORMATO_MAXIMO) {
    c.aviso(
      "manifiesto",
      "manifiesto.formato",
      "Formato de manifiesto conocido",
      `El manifiesto declara formato ${m.formato} y este verificador entiende hasta el ${FORMATO_MAXIMO}. Los chequeos corren igual, pero puede haber campos nuevos que no se miran.`,
    );
  } else {
    c.falla(
      "manifiesto",
      "manifiesto.formato",
      "Formato de manifiesto conocido",
      `Formato ${JSON.stringify(m.formato)}, inesperado.`,
    );
  }

  c.segun(
    esHex32(m?.documento?.hash),
    "manifiesto",
    "manifiesto.hash",
    "El hash declarado tiene forma de SHA-256",
    m?.documento?.hash,
    `${JSON.stringify(m?.documento?.hash)} no es 0x + 64 hex.`,
  );

  const w = dir(m?.emisor?.wallet);
  c.segun(
    Boolean(w),
    "manifiesto",
    "manifiesto.emisor",
    "La wallet del emisor es una dirección válida",
    `${m?.emisor?.email} — ${w}`,
    `${JSON.stringify(m?.emisor?.wallet)} no es una dirección.`,
  );

  // Fechas: creado ≤ última firma ≤ generado. Un manifiesto que dice haberse
  // generado antes de la firma que describe se contradice solo.
  const creado = fecha(m?.fechas?.creado);
  const ultima = fecha(m?.fechas?.ultimaFirma);
  const generado = fecha(m?.generadoEl);
  const coherente =
    creado &&
    generado &&
    (!ultima || (ultima >= creado && ultima <= generado)) &&
    creado <= generado;
  c.segun(
    Boolean(coherente),
    "manifiesto",
    "manifiesto.fechas",
    "Las fechas del manifiesto son coherentes entre sí",
    `creado ${m?.fechas?.creado}${ultima ? ` · última firma ${m.fechas.ultimaFirma}` : ""} · generado ${m?.generadoEl}`,
    "La creación, la última firma y la generación no están en orden.",
  );

  const firmantes = Array.isArray(m.firmantes) ? m.firmantes : [];
  const sinFirmar = firmantes.filter((f) => f.estado !== "SIGNED");
  if (firmantes.length === 0) {
    c.falla("manifiesto", "manifiesto.firmantes", "Hay al menos un firmante", "La lista está vacía.");
  } else if (sinFirmar.length > 0) {
    // El servidor solo arma el manifiesto con el documento COMPLETED, así que
    // esto no debería pasar nunca: si pasa, el manifiesto no es el que arma
    // sygners.
    c.falla(
      "manifiesto",
      "manifiesto.firmantes",
      "Todos los firmantes figuran como firmados",
      `${sinFirmar.length} de ${firmantes.length} no están en SIGNED: ${sinFirmar
        .map((f) => `${f.email} (${f.estado})`)
        .join(", ")}`,
    );
  } else {
    c.ok(
      "manifiesto",
      "manifiesto.firmantes",
      "Todos los firmantes figuran como firmados",
      `${firmantes.length} firmante(s)`,
    );
  }
}

// ── 3. El documento contra lo que el manifiesto declara ──────────────────────
function chequearDocumento(c, zip, m) {
  if (!zip.documento) {
    c.falla("documento", "documento.hash", "El documento es el que quedó anclado", "No hay documento que hashear.");
    return null;
  }
  const calculado = sha256Hex(zip.documento);
  const declarado = m?.documento?.hash;

  // EL chequeo. Todo lo demás describe; este prueba.
  c.segun(
    hashesIguales(calculado, declarado),
    "documento",
    "documento.hash",
    "El SHA-256 del documento es el que declara el manifiesto",
    calculado,
    `Calculado ${calculado}, declarado ${declarado}. El archivo que viene adentro NO es el que se firmó.`,
    { esperado: declarado ?? null, obtenido: calculado },
  );

  const tam = m?.documento?.tamano;
  if (typeof tam === "number") {
    c.segun(
      tam === zip.documento.length,
      "documento",
      "documento.tamano",
      "El tamaño coincide con el declarado",
      `${zip.documento.length} bytes`,
      `El manifiesto dice ${tam} bytes y el archivo tiene ${zip.documento.length}.`,
    );
  }

  const nombre = m?.documento?.nombreArchivo;
  if (nombre) {
    c[nombre === zip.nombreDocumento ? "ok" : "aviso"](
      "documento",
      "documento.nombre",
      "El nombre del archivo coincide con el declarado",
      nombre === zip.nombreDocumento
        ? nombre
        : `El zip lo trae como "${zip.nombreDocumento}" y el manifiesto lo llama "${nombre}". El nombre no es parte de lo anclado; lo que prueba la identidad del archivo es el hash.`,
    );
  }

  // El LEEME.txt repite el hash en prosa. Que no coincida con el manifiesto
  // significa que alguien editó una de las dos piezas.
  if (zip.leeme && esHex32(declarado)) {
    const enLeeme = zip.leeme.includes(declarado);
    c[enLeeme ? "ok" : "falla"](
      "documento",
      "documento.leeme",
      "El LEEME repite el mismo hash que el manifiesto",
      enLeeme ? null : "El hash escrito en LEEME.txt no es el del manifiesto: alguien tocó una de las dos piezas.",
    );
  }

  return calculado;
}

// ── 3.5 Las firmas EIP-712, sin red ──────────────────────────────────────────
//
// Este bloque es el que cambió lo que un paquete prueba por sí solo. No consulta
// nada: recupera la dirección desde la firma cruda y la compara con la
// declarada. Si da, esa wallet firmó ese mensaje, y no hay que creerle a la
// cadena ni a sygners para saberlo.
function chequearFirmasCrudas(c, m, opts) {
  const firmantes = Array.isArray(m.firmantes) ? m.firmantes : [];
  const chainId = Number(m?.cadena?.chainId);

  if (!(m.formato >= FORMATO_CON_FIRMA_CRUDA)) {
    c.omitido(
      "firmas",
      "firma.crudas",
      "Recuperar la dirección desde la firma",
      `El manifiesto es de formato ${m.formato}, anterior a que el paquete llevara la firma cruda. Lo que quedó anclado on-chain es la huella (keccak256 de la firma), no la firma, así que desde este paquete no hay nada que recuperar.`,
    );
    return;
  }

  // El dominio del paquete se verifica, no se usa a ciegas: uno elegido a
  // medida haría que una firma hecha en otro lado recupere limpia acá.
  const cmp = compararEip712(m.eip712, chainId);
  c.segun(
    cmp.ok,
    "firmas",
    "firma.eip712",
    "El dominio y los tipos EIP-712 del paquete son los de sygners",
    `sygners · v1 · chainId ${chainId}`,
    `El paquete declara otro esquema de firma: ${cmp.problemas.join("; ")}. La recuperación corre igual con el dominio canónico.`,
  );

  // La wallet del emisor no firma: identifica al registro on-chain. Cuando
  // quien emite además firma, aparece dos veces con direcciones distintas, y
  // eso confunde lo suficiente como para escribirlo.
  const emisorTambienFirma = firmantes.some(
    (f) => String(f.email).toLowerCase() === String(m?.emisor?.email ?? "").toLowerCase(),
  );
  if (emisorTambienFirma) {
    c.info(
      "firmas",
      "firma.emisor",
      "El emisor también firma",
      `La wallet del emisor (${m?.emisor?.wallet}) es la del REGISTRO y no firma nada, así que no se recupera de ninguna firma. Las que se verifican son las de firmantes[].wallet: que sean distintas es lo esperado.`,
    );
  }

  for (const [i, f] of firmantes.entries()) {
    const etiqueta = f.email ?? `firmante ${i + 1}`;

    if (f.firma === null || f.firma === undefined) {
      c.aviso(
        "firmas",
        `firma.${i}.cruda`,
        `${etiqueta}: el paquete trae su firma cruda`,
        "No la trae. Es una firma anterior al formato 2 (o un firmante que nunca firmó): su evidencia sigue siendo la attestation on-chain, pero no se puede recuperar la dirección acá.",
      );
      continue;
    }
    if (!esFirmaBienFormada(f.firma)) {
      c.falla("firmas", `firma.${i}.cruda`, `${etiqueta}: su firma tiene forma de firma`, `${JSON.stringify(f.firma)} no son 65 bytes en hex.`);
      continue;
    }
    if (!f.mensaje || typeof f.mensaje !== "object") {
      c.falla(
        "firmas",
        `firma.${i}.mensaje`,
        `${etiqueta}: el paquete trae el mensaje que firmó`,
        "Viene la firma pero no el mensaje: no hay nada contra qué verificarla.",
      );
      continue;
    }

    // Qué dice el mensaje que se firmó. Una firma válida sobre otro documento,
    // otra persona o otra declaración no dice nada de esta operación.
    const msj = f.mensaje;
    c.segun(
      hashesIguales(msj.documentHash, m?.documento?.hash),
      "firmas",
      `firma.${i}.mensaje.hash`,
      `${etiqueta}: firmó el hash de ESTE documento`,
      msj.documentHash,
      `Firmó ${msj.documentHash}, y el documento del paquete es ${m?.documento?.hash}.`,
    );
    c.segun(
      msj.documentId === m?.documento?.id,
      "firmas",
      `firma.${i}.mensaje.id`,
      `${etiqueta}: firmó esta operación`,
      msj.documentId,
      `El mensaje dice ${JSON.stringify(msj.documentId)} y la operación es ${JSON.stringify(m?.documento?.id)}.`,
    );
    c.segun(
      String(msj.signerEmail).toLowerCase() === String(f.email ?? "").toLowerCase(),
      "firmas",
      `firma.${i}.mensaje.email`,
      `${etiqueta}: firmó con su propio correo`,
      msj.signerEmail,
      `El mensaje dice ${msj.signerEmail} y el firmante es ${f.email}.`,
    );
    c.segun(
      msj.statement === DECLARACION,
      "firmas",
      `firma.${i}.mensaje.declaracion`,
      `${etiqueta}: aceptó la declaración de sygners`,
      msj.statement,
      `Aceptó otro texto: ${JSON.stringify(msj.statement)}.`,
    );

    // LA comprobación: la dirección sale de la firma.
    const r = recuperarFirmante(msj, f.firma, chainId);
    if (!r.ok) {
      c.falla("firmas", `firma.${i}.recuperada`, `${etiqueta}: su firma se puede verificar`, r.error);
    } else {
      c.segun(
        mismaDireccion(r.direccion, f.wallet),
        "firmas",
        `firma.${i}.recuperada`,
        `${etiqueta}: la dirección recuperada de su firma es la declarada`,
        r.direccion,
        `La firma la produjo ${r.direccion}, y el manifiesto declara ${f.wallet}.`,
        { esperado: f.wallet ?? null, obtenido: r.direccion },
      );
    }

    // Y la huella, que es la mitad que quedó escrita en la cadena.
    const h = huella(f.firma);
    if (f.sigHash) {
      c.segun(
        hashesIguales(h, f.sigHash),
        "firmas",
        `firma.${i}.huella`,
        `${etiqueta}: la huella declarada es la de su firma`,
        h,
        `keccak256 de la firma da ${h} y el manifiesto declara ${f.sigHash}.`,
      );
    } else {
      c.aviso("firmas", `firma.${i}.huella`, `${etiqueta}: el manifiesto declara la huella de su firma`, "No la declara; se recalcula desde la firma para cotejarla con la cadena.");
    }

    // El timestamp lo asevera quien firma; `firmadoEl` es el reloj del
    // servidor. Que estén lejos no invalida la firma, pero se dice.
    const declarada = fecha(f.firmadoEl);
    if (declarada && Number.isFinite(Number(msj.timestamp))) {
      const delta = Math.abs(seg(declarada) - Number(msj.timestamp));
      c[delta <= opts.toleranciaSegundos ? "ok" : "aviso"](
        "firmas",
        `firma.${i}.mensaje.fecha`,
        `${etiqueta}: la fecha que firmó y la registrada están cerca`,
        delta <= opts.toleranciaSegundos
          ? `${new Date(Number(msj.timestamp) * 1000).toISOString()} (${delta}s)`
          : `El mensaje dice ${new Date(Number(msj.timestamp) * 1000).toISOString()} y el manifiesto registró ${f.firmadoEl}: ${delta}s de diferencia.`,
      );
    }
  }
}

// ── 4. La cadena ─────────────────────────────────────────────────────────────
async function chequearCadena(c, m, opts) {
  const chainId = Number(m?.cadena?.chainId);
  const cadena = cadenaDe(chainId, opts);
  const esperado = expectativas(chainId, opts);
  const resultado = { cadena, atestaciones: {} };

  if (!cadena.conocida) {
    c.aviso(
      "cadena",
      "cadena.conocida",
      "La cadena del manifiesto es conocida",
      `chainId ${chainId} no está en la tabla del verificador. Configurá RPC_URL_${chainId}, EAS_CONTRACT_ADDRESS_${chainId} y SCHEMA_REGISTRY_ADDRESS_${chainId}.`,
    );
  } else {
    c.ok("cadena", "cadena.conocida", "La cadena del manifiesto es conocida", `${cadena.nombre} (chainId ${chainId})`);
  }
  if (cadena.prueba) {
    c.aviso(
      "cadena",
      "cadena.prueba",
      "La cadena es una red de producción",
      `${cadena.nombre} es una RED DE PRUEBA. El anclaje se comprueba igual y todo lo de abajo vale, pero una testnet no cuesta nada de producir y puede reiniciarse entera: como prueba de que el documento existía en esa fecha, no tiene el mismo valor que una red de producción. Un paquete que tenga que sostenerse frente a un tercero debería estar anclado en una red de producción.`,
    );
  }
  if (!cadena.rpcPropio) {
    c.aviso(
      "cadena",
      "cadena.rpc",
      "El RPC es uno que controlás",
      `Se usó el nodo público por defecto (${cadena.rpcUrl}). Sirve para verificar, pero para una verificación que tenga que sostenerse frente a un tercero conviene apuntar a tu propio nodo con RPC_URL_${chainId}.`,
    );
  }
  if (!cadena.rpcUrl || !cadena.eas) {
    c.falla(
      "cadena",
      "cadena.config",
      "Hay con qué consultar la cadena",
      `Falta ${!cadena.rpcUrl ? `RPC_URL_${chainId}` : `EAS_CONTRACT_ADDRESS_${chainId}`}.`,
    );
    return resultado;
  }

  const prov = proveedor(cadena, opts.timeoutMs);
  try {
    const idNodo = await chainIdDelNodo(prov);
    if (idNodo !== chainId) {
      c.falla(
        "cadena",
        "cadena.id",
        "El nodo RPC es el de la cadena que declara el manifiesto",
        `El manifiesto dice ${chainId} y el nodo contesta ${idNodo}. No se verifica nada contra la red equivocada.`,
      );
      return resultado;
    }
    c.ok("cadena", "cadena.id", "El nodo RPC es el de la cadena que declara el manifiesto", `chainId ${idNodo}`);
  } catch (e) {
    c.falla("cadena", "cadena.id", "El nodo RPC responde", `${cadena.rpcUrl}: ${e?.shortMessage ?? e?.message ?? e}`);
    return resultado;
  }

  // 4.1 El registro del documento.
  const regUid = m?.cadena?.registroUid;
  let registro = null;
  if (!esHex32(regUid)) {
    c.falla("cadena", "registro.uid", "El manifiesto trae el UID del registro", `${JSON.stringify(regUid)} no es un UID.`);
  } else {
    registro = await leerUna(c, prov, cadena, regUid, "registro", "El registro del documento existe en la cadena");
  }

  if (registro) {
    resultado.atestaciones.registro = registro;
    const d = decodificarDatos(registro.data);
    if (!d.ok) {
      c.falla("cadena", "registro.datos", "El registro se decodifica con el schema de sygners", d.error);
    } else {
      c.segun(
        hashesIguales(d.documentHash, m?.documento?.hash),
        "cadena",
        "registro.hash",
        "El hash anclado es el del documento del paquete",
        d.documentHash,
        `En la cadena está anclado ${d.documentHash} y el paquete declara ${m?.documento?.hash}.`,
        { esperado: m?.documento?.hash ?? null, obtenido: d.documentHash },
      );
      c.segun(
        d.action === ACCION_REGISTRO,
        "cadena",
        "registro.accion",
        "La atestación del registro dice REGISTER",
        d.action,
        `Dice "${d.action}".`,
      );
      c.segun(
        d.email?.toLowerCase() === String(m?.emisor?.email ?? "").toLowerCase(),
        "cadena",
        "registro.emisor.email",
        "El emisor anclado es el del manifiesto",
        d.email,
        `En la cadena: ${d.email}. En el manifiesto: ${m?.emisor?.email}.`,
      );
      c.segun(
        dir(d.subject) && dir(d.subject) === dir(m?.emisor?.wallet),
        "cadena",
        "registro.emisor.wallet",
        "La wallet del emisor anclada es la del manifiesto",
        d.subject,
        `En la cadena: ${d.subject}. En el manifiesto: ${m?.emisor?.wallet}.`,
      );
    }
    await chequearSchema(c, prov, cadena, registro.schema, esperado);
    chequearAttester(c, registro.attester, esperado, "registro");
  }

  // 4.2 Cada firma.
  const firmantes = Array.isArray(m.firmantes) ? m.firmantes : [];
  resultado.atestaciones.firmas = [];
  for (const [i, f] of firmantes.entries()) {
    const etiqueta = f.email ?? `firmante ${i + 1}`;
    if (!esHex32(f.attestationUid)) {
      c.falla("firmas", `firma.${i}.uid`, `${etiqueta}: el manifiesto trae el UID de su firma`, `${JSON.stringify(f.attestationUid)} no es un UID.`);
      continue;
    }
    const a = await leerUna(c, prov, cadena, f.attestationUid, `firma.${i}`, `${etiqueta}: su firma existe en la cadena`);
    if (!a) continue;
    resultado.atestaciones.firmas.push({ email: f.email, atestacion: a });

    const d = decodificarDatos(a.data);
    if (!d.ok) {
      c.falla("firmas", `firma.${i}.datos`, `${etiqueta}: su firma se decodifica con el schema de sygners`, d.error);
      continue;
    }
    c.segun(
      d.action === ACCION_FIRMA,
      "firmas",
      `firma.${i}.accion`,
      `${etiqueta}: la atestación dice SIGN`,
      d.action,
      `Dice "${d.action}".`,
    );
    c.segun(
      hashesIguales(d.documentHash, m?.documento?.hash),
      "firmas",
      `firma.${i}.hash`,
      `${etiqueta}: firmó ESTE documento`,
      d.documentHash,
      `Su firma está anclada sobre ${d.documentHash}, que no es el documento de este paquete.`,
    );
    c.segun(
      d.email?.toLowerCase() === String(f.email ?? "").toLowerCase(),
      "firmas",
      `firma.${i}.email`,
      `${etiqueta}: el correo anclado es el del manifiesto`,
      d.email,
      `En la cadena: ${d.email}. En el manifiesto: ${f.email}.`,
    );
    c.segun(
      dir(d.subject) && dir(d.subject) === dir(f.wallet),
      "firmas",
      `firma.${i}.wallet`,
      `${etiqueta}: la wallet anclada es la del manifiesto`,
      d.subject,
      `En la cadena: ${d.subject}. En el manifiesto: ${f.wallet}.`,
    );
    // La huella anclada. Con el formato 2 esto deja de ser "hay algo escrito" y
    // pasa a ser el nudo de toda la evidencia: la firma que trae el paquete es,
    // byte a byte, la que se ancló en la cadena.
    const huellaDelPaquete = esFirmaBienFormada(f.firma) ? huella(f.firma) : null;
    if (huellaDelPaquete) {
      c.segun(
        hashesIguales(d.sigHash, huellaDelPaquete),
        "firmas",
        `firma.${i}.sighash`,
        `${etiqueta}: la firma del paquete es la que quedó anclada`,
        d.sigHash,
        `En la cadena quedó la huella ${d.sigHash} y la firma que trae el paquete da ${huellaDelPaquete}: no es la misma firma.`,
      );
    } else {
      c.segun(
        d.sigHash && d.sigHash !== BYTES32_CERO,
        "firmas",
        `firma.${i}.sighash`,
        `${etiqueta}: la atestación lleva la huella de su firma EIP-712`,
        d.sigHash,
        "El campo sigHash viene en cero: la atestación no ata ninguna firma.",
      );
    }
    // La firma referencia al registro: es lo que las une en un solo expediente.
    if (registro) {
      c.segun(
        a.refUID?.toLowerCase() === registro.uid.toLowerCase(),
        "firmas",
        `firma.${i}.ref`,
        `${etiqueta}: su firma referencia al registro del documento`,
        a.refUID,
        `Referencia a ${a.refUID}, no al registro ${registro.uid}.`,
      );
      c.segun(
        a.schema?.toLowerCase() === registro.schema?.toLowerCase(),
        "firmas",
        `firma.${i}.schema`,
        `${etiqueta}: usa el mismo schema que el registro`,
        a.schema,
        `Schema ${a.schema}, distinto del ${registro.schema} del registro.`,
      );
    }
    chequearAttester(c, a.attester, esperado, `firma.${i}`, etiqueta);

    // La fecha que declara el manifiesto contra la que quedó en el bloque.
    const declarada = fecha(f.firmadoEl);
    if (declarada && a.time) {
      const delta = Math.abs(seg(declarada) - a.time);
      const dentro = delta <= opts.toleranciaSegundos;
      c[dentro ? "ok" : "aviso"](
        "firmas",
        `firma.${i}.fecha`,
        `${etiqueta}: la fecha declarada y la del bloque están cerca`,
        dentro
          ? `${f.firmadoEl} · en cadena ${new Date(a.time * 1000).toISOString()} (${delta}s)`
          : `El manifiesto dice ${f.firmadoEl} y el bloque ${new Date(a.time * 1000).toISOString()}: ${delta}s de diferencia. El anclaje siempre es posterior a la firma, pero una diferencia grande merece mirarse.`,
      );
    }
  }

  // 4.3 Los recibos de transacción (opcional).
  if (opts.verificarTx) {
    const pares = [
      ["registro", m?.cadena?.registroTxHash, "El registro"],
      ...firmantes.map((f, i) => [`firma.${i}`, f.txHash, f.email]),
    ];
    for (const [id, hash, etiqueta] of pares) {
      const quien = etiqueta ? `${etiqueta}: ` : "";
      if (!esHex32(hash)) {
        c.aviso("cadena", `${id}.tx`, `${quien}tiene hash de transacción`, `${JSON.stringify(hash)} no es un hash.`);
        continue;
      }
      try {
        const r = await leerRecibo(prov, hash);
        if (!r) {
          c.falla("cadena", `${id}.tx`, `${quien}la transacción existe en la cadena`, `No hay recibo para ${hash}.`);
        } else if (r.status !== 1) {
          c.falla("cadena", `${id}.tx`, `${quien}la transacción se ejecutó bien`, `status ${r.status}.`);
        } else if (dir(r.to) !== dir(cadena.eas)) {
          c.falla(
            "cadena",
            `${id}.tx`,
            `${quien}la transacción fue al contrato de EAS`,
            `Fue a ${r.to}, no a ${cadena.eas}.`,
          );
        } else {
          c.ok("cadena", `${id}.tx`, `${quien}la transacción existe y fue a EAS`, `bloque ${r.blockNumber} · ${hash}`);
        }
      } catch (e) {
        c.aviso("cadena", `${id}.tx`, `${quien}se pudo pedir el recibo`, e?.shortMessage ?? e?.message ?? String(e));
      }
    }
  } else {
    c.omitido("cadena", "tx", "Recibos de transacción", "VERIFICAR_TX=false");
  }

  return resultado;
}

async function leerUna(c, prov, cadena, uid, id, titulo) {
  try {
    const a = await leerAtestacion(prov, cadena, uid);
    if (!a) {
      c.falla(
        "cadena",
        `${id}.existe`,
        titulo,
        `No hay ninguna atestación con UID ${uid} en ${cadena.nombre}. O el paquete la inventó, o se ancló en otra red.`,
      );
      return null;
    }
    if (a.revocationTime && a.revocationTime > 0) {
      c.falla(
        "cadena",
        `${id}.existe`,
        titulo,
        `Existe, pero fue REVOCADA el ${new Date(a.revocationTime * 1000).toISOString()}.`,
      );
      return a;
    }
    if (a.expirationTime && a.expirationTime > 0 && a.expirationTime * 1000 < Date.now()) {
      c.aviso("cadena", `${id}.existe`, titulo, `Existe, pero venció el ${new Date(a.expirationTime * 1000).toISOString()}.`);
      return a;
    }
    c.ok("cadena", `${id}.existe`, titulo, `${uid} · anclada el ${new Date(a.time * 1000).toISOString()} · ${cadena.urlAtestacion(uid) ?? ""}`.trim());
    return a;
  } catch (e) {
    c.falla("cadena", `${id}.existe`, titulo, `No se pudo consultar: ${e?.shortMessage ?? e?.message ?? e}`);
    return null;
  }
}

function chequearAttester(c, attester, esperado, id, etiqueta) {
  const quien = etiqueta ? `${etiqueta}: ` : "";
  if (!esperado.attester) {
    c.info("cadena", `${id}.attester`, `${quien}quién ancló`, `${attester} (configurá SYGNERS_ATTESTER para exigir una en particular)`);
    return;
  }
  c.segun(
    dir(attester) && dir(attester) === dir(esperado.attester),
    "cadena",
    `${id}.attester`,
    `${quien}la ancló el atestador esperado`,
    attester,
    `La ancló ${attester}, y esperabas ${esperado.attester}.`,
  );
}

async function chequearSchema(c, prov, cadena, schemaUid, esperado) {
  if (esperado.schemaUid) {
    c.segun(
      schemaUid?.toLowerCase() === esperado.schemaUid.toLowerCase(),
      "cadena",
      "schema.uid",
      "Las atestaciones usan el schema esperado",
      schemaUid,
      `Usan ${schemaUid} y esperabas ${esperado.schemaUid}.`,
    );
  } else {
    c.info("cadena", "schema.uid", "Schema usado", `${schemaUid} (configurá EAS_SCHEMA_UID para exigir uno)`);
  }
  if (!cadena.registry) return;
  try {
    const s = await leerSchema(prov, cadena, schemaUid);
    if (!s) {
      c.aviso("cadena", "schema.definicion", "El schema está registrado en la cadena", `No se encontró ${schemaUid} en el SchemaRegistry.`);
      return;
    }
    const norm = (t) => String(t).replace(/\s+/g, " ").trim();
    c.segun(
      norm(s.schema) === norm(SCHEMA_DEFINICION),
      "cadena",
      "schema.definicion",
      "El schema on-chain es el de sygners",
      s.schema,
      `On-chain: "${s.schema}". Esperado: "${SCHEMA_DEFINICION}".`,
    );
  } catch (e) {
    c.aviso("cadena", "schema.definicion", "Se pudo leer el schema del registro", e?.shortMessage ?? e?.message ?? String(e));
  }
}

// ── Orquestación ─────────────────────────────────────────────────────────────
export async function verificarEvidencia(bytes, opts) {
  const c = new Chequeos();
  const zip = abrirEvidencia(bytes);

  if (!zip.ok) {
    c.falla("archivo", "zip", "El archivo es un .zip legible", zip.error);
    return armarResultado(c, { opts, zip: null, manifiesto: null, simulado: { simulado: false, motivos: [] } });
  }

  chequearEstructura(c, zip);

  const m = zip.manifiesto;
  if (!m) {
    c.falla("manifiesto", "manifiesto.json", "El manifiesto se puede leer", zip.errorManifiesto);
    return armarResultado(c, { opts, zip, manifiesto: null, simulado: { simulado: false, motivos: [] } });
  }
  c.ok("manifiesto", "manifiesto.json", "El manifiesto se puede leer", `${zip.manifiestoCrudo.length} bytes de JSON`);

  chequearManifiesto(c, m);
  const hashCalculado = chequearDocumento(c, zip, m);

  // Las firmas se verifican SIN red: desde el formato 2, un paquete prueba por
  // sí solo que esas wallets firmaron: recuperar la dirección no necesita la
  // cadena, solo la firma y el mensaje.
  chequearFirmasCrudas(c, m, opts);

  // Lo simulado se detecta SIN red, y antes de tocarla: si el paquete salió de
  // un entorno sin cadena, consultar la cadena solo va a confirmar que no hay
  // nada, y el informe tiene que decir por qué.
  const sim = detectarSimulado(m);
  if (sim.simulado) {
    c.falla(
      "cadena",
      "cadena.simulado",
      "La evidencia está anclada de verdad (no es del modo simulado)",
      `Los identificadores on-chain de este paquete son los que sygners genera cuando NO tiene cadena configurada: ${sim.motivos.join("; ")}. El documento y el manifiesto pueden ser correctos, pero NO hay nada anclado: esto no prueba la existencia del documento en ninguna fecha.`,
    );
  }

  let cadena = null;
  if (opts.sinCadena) {
    c.omitido("cadena", "cadena", "Cotejo contra la cadena", "Pedido con --sin-cadena / SIN_CADENA=true.");
  } else if (sim.simulado) {
    c.omitido("cadena", "cadena", "Cotejo contra la cadena", "No se consulta: los identificadores son simulados.");
  } else {
    cadena = await chequearCadena(c, m, opts);
  }

  return armarResultado(c, { opts, zip, manifiesto: m, simulado: sim, hashCalculado, cadena });
}

function armarResultado(c, ctx) {
  const fallas = c.cuenta("falla");
  const avisos = c.cuenta("aviso");
  const omitidos = c.cuenta("omitido");
  const estrictoFalla = ctx.opts.estricto && avisos > 0;

  let veredicto;
  if (fallas > 0 || estrictoFalla) veredicto = ctx.simulado?.simulado ? "SIMULADO" : "NO_VERIFICA";
  else if (ctx.opts.sinCadena) veredicto = "PARCIAL";
  else veredicto = "VERIFICADO";

  const m = ctx.manifiesto;
  const cadenaId = Number(m?.cadena?.chainId);
  const cfg = Number.isFinite(cadenaId) ? cadenaDe(cadenaId, ctx.opts) : null;

  return {
    veredicto,
    resumen: { ok: c.cuenta("ok"), fallas, avisos, omitidos },
    chequeos: c.lista,
    operacion: m
      ? {
          documentoId: m.documento?.id ?? null,
          titulo: m.documento?.titulo ?? null,
          archivo: ctx.zip?.nombreDocumento ?? null,
          hashDeclarado: m.documento?.hash ?? null,
          hashCalculado: ctx.hashCalculado ?? null,
          chainId: Number.isFinite(cadenaId) ? cadenaId : null,
          red: cfg?.nombre ?? null,
          registroUid: m.cadena?.registroUid ?? null,
          registroUrl: cfg?.urlAtestacion(m.cadena?.registroUid) ?? null,
          emisor: m.emisor ?? null,
          firmantes: (m.firmantes ?? []).map((f) => ({
            ...f,
            url: cfg?.urlAtestacion(f.attestationUid) ?? null,
          })),
          fechas: m.fechas ?? null,
          generadoEl: m.generadoEl ?? null,
          simulado: Boolean(ctx.simulado?.simulado),
        }
      : null,
  };
}
