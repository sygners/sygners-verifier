// Qué cadena es cada chainId, dónde vive EAS en ella y con qué RPC se la
// consulta.
//
// Todo lo de acá es reemplazable por una variable de entorno. Los defaults
// existen para que el verificador funcione recién descargado; las variables,
// para que nadie tenga que confiar en ellos.

import { env, envBool, envNum } from "./env.js";

// Direcciones oficiales de EAS (docs.attest.org). En las cadenas OP-stack son
// predeploys y por eso se repiten.
export const CADENAS = {
  1: {
    nombre: "Ethereum",
    eas: "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
    registry: "0xA7b39296258348C78294F95B872b282326A97BDF",
    rpc: "https://ethereum-rpc.publicnode.com",
    easscan: "https://easscan.org",
    tx: "https://etherscan.io",
  },
  11155111: {
    nombre: "Ethereum Sepolia",
    prueba: true,
    eas: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",
    registry: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
    rpc: "https://ethereum-sepolia-rpc.publicnode.com",
    easscan: "https://sepolia.easscan.org",
    tx: "https://sepolia.etherscan.io",
  },
  8453: {
    nombre: "Base",
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://base-rpc.publicnode.com",
    easscan: "https://base.easscan.org",
    tx: "https://basescan.org",
  },
  11155420: {
    nombre: "OP Sepolia",
    prueba: true,
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://sepolia.optimism.io",
    easscan: "https://optimism-sepolia.easscan.org",
    tx: "https://sepolia-optimism.etherscan.io",
  },
  84532: {
    nombre: "Base Sepolia",
    prueba: true,
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://base-sepolia-rpc.publicnode.com",
    easscan: "https://base-sepolia.easscan.org",
    tx: "https://sepolia.basescan.org",
  },
  10: {
    nombre: "OP Mainnet",
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://optimism-rpc.publicnode.com",
    easscan: "https://optimism.easscan.org",
    tx: "https://optimistic.etherscan.io",
  },
  42161: {
    nombre: "Arbitrum One",
    eas: "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
    registry: "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
    rpc: "https://arbitrum-one-rpc.publicnode.com",
    easscan: "https://arbitrum.easscan.org",
    tx: "https://arbiscan.io",
  },
  137: {
    nombre: "Polygon",
    eas: "0x5E634ef5355f45A855d02D66eCD687b1502AF790",
    registry: "0x7876EEF51A891E737AF8ba5A5E0f0Fd29073D5a7",
    rpc: "https://polygon-bor-rpc.publicnode.com",
    easscan: "https://polygon.easscan.org",
    tx: "https://polygonscan.com",
  },
};

// La definición del schema con la que sygners ancla registro y firmas.
export const SCHEMA_DEFINICION =
  env("SYGNERS_SCHEMA_DEFINICION") ??
  "bytes32 documentHash,string action,string email,address subject,bytes32 sigHash";

export const ACCION_REGISTRO = "REGISTER";
export const ACCION_FIRMA = "SIGN";
export const BYTES32_CERO = `0x${"00".repeat(32)}`;

// Opciones globales, tomadas del entorno y pisables por la línea de comandos.
export function opciones(flags = {}) {
  return {
    sinCadena: flags.sinCadena ?? envBool("SIN_CADENA", false),
    verificarTx: flags.verificarTx ?? envBool("VERIFICAR_TX", true),
    estricto: flags.estricto ?? envBool("ESTRICTO", false),
    toleranciaSegundos: flags.toleranciaSegundos ?? envNum("TOLERANCIA_FECHA_SEGUNDOS", 3600),
    timeoutMs: flags.timeoutMs ?? envNum("RPC_TIMEOUT_MS", 20000),
    // Las expectativas se resuelven por cadena (ver `expectativas`): quien
    // corre varios entornos —producción en una red, preproducción en otra—
    // tiene un schema y un relayer distintos en cada una, y un único valor
    // global haría fallar al otro entorno por una diferencia esperada.
    schemaUidFlag: flags.schemaUid ?? null,
    attesterFlag: flags.attester ?? null,
    rpcForzado: flags.rpc ?? null,
  };
}

// Qué se le exige a las atestaciones de ESTA cadena. Precedencia: la línea de
// comandos, después `<VARIABLE>_<chainId>`, y al final la variable sin sufijo.
export function expectativas(chainId, opts = {}) {
  return {
    schemaUid: opts.schemaUidFlag ?? env(`EAS_SCHEMA_UID_${chainId}`) ?? env("EAS_SCHEMA_UID") ?? null,
    attester: opts.attesterFlag ?? env(`SYGNERS_ATTESTER_${chainId}`) ?? env("SYGNERS_ATTESTER") ?? null,
  };
}

// La configuración de UNA cadena, la que dice el manifiesto.
//
// ⚠️ El chainId sale del manifiesto y no del entorno, por la misma razón por la
// que sygners lo guarda por documento: una operación vive en la red donde se
// ancló, y verificar contra la red de hoy rechazaría todo lo anterior a un
// cambio de red.
export function cadenaDe(chainId, opts = {}) {
  const base = CADENAS[chainId] ?? null;
  const rpcUrl =
    opts.rpcForzado ??
    env(`RPC_URL_${chainId}`) ??
    env("RPC_URL") ??
    base?.rpc ??
    null;
  return {
    chainId,
    nombre: base?.nombre ?? `cadena ${chainId}`,
    conocida: Boolean(base),
    // Una red de prueba no tiene el mismo valor probatorio: sus bloques no
    // cuestan nada de producir y la red puede reiniciarse entera.
    prueba: Boolean(base?.prueba),
    rpcUrl,
    rpcPropio: Boolean(opts.rpcForzado || env(`RPC_URL_${chainId}`) || env("RPC_URL")),
    eas: env(`EAS_CONTRACT_ADDRESS_${chainId}`) ?? env("EAS_CONTRACT_ADDRESS") ?? base?.eas ?? null,
    registry:
      env(`SCHEMA_REGISTRY_ADDRESS_${chainId}`) ??
      env("SCHEMA_REGISTRY_ADDRESS") ??
      base?.registry ??
      null,
    urlAtestacion: (uid) => (base?.easscan && uid ? `${base.easscan}/attestation/view/${uid}` : null),
    urlTx: (hash) => (base?.tx && hash ? `${base.tx}/tx/${hash}` : null),
  };
}
