// Which chain each chainId is, where EAS lives on it, and which RPC to ask.
//
// Everything here can be replaced by an environment variable. The defaults
// exist so the verifier works right after being downloaded; the variables, so
// nobody has to trust them.

import { env, envBool } from "./env.js";

// Official EAS addresses (docs.attest.org). On OP-stack chains they are
// predeploys, which is why they repeat.
export const CHAINS = {
  1: {
    name: "Ethereum",
    eas: "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
    registry: "0xA7b39296258348C78294F95B872b282326A97BDF",
    rpc: "https://ethereum-rpc.publicnode.com",
    easscan: "https://easscan.org",
    tx: "https://etherscan.io",
  },
  11155111: {
    name: "Ethereum Sepolia",
    testnet: true,
    eas: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",
    registry: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
    rpc: "https://ethereum-sepolia-rpc.publicnode.com",
    easscan: "https://sepolia.easscan.org",
    tx: "https://sepolia.etherscan.io",
  },
  8453: {
    name: "Base",
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://base-rpc.publicnode.com",
    easscan: "https://base.easscan.org",
    tx: "https://basescan.org",
  },
  11155420: {
    name: "OP Sepolia",
    testnet: true,
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://sepolia.optimism.io",
    easscan: "https://optimism-sepolia.easscan.org",
    tx: "https://sepolia-optimism.etherscan.io",
  },
  84532: {
    name: "Base Sepolia",
    testnet: true,
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://base-sepolia-rpc.publicnode.com",
    easscan: "https://base-sepolia.easscan.org",
    tx: "https://sepolia.basescan.org",
  },
  10: {
    name: "OP Mainnet",
    eas: "0x4200000000000000000000000000000000000021",
    registry: "0x4200000000000000000000000000000000000020",
    rpc: "https://optimism-rpc.publicnode.com",
    easscan: "https://optimism.easscan.org",
    tx: "https://optimistic.etherscan.io",
  },
  42161: {
    name: "Arbitrum One",
    eas: "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
    registry: "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
    rpc: "https://arbitrum-one-rpc.publicnode.com",
    easscan: "https://arbitrum.easscan.org",
    tx: "https://arbiscan.io",
  },
  137: {
    name: "Polygon",
    eas: "0x5E634ef5355f45A855d02D66eCD687b1502AF790",
    registry: "0x7876EEF51A891E737AF8ba5A5E0f0Fd29073D5a7",
    rpc: "https://polygon-bor-rpc.publicnode.com",
    easscan: "https://polygon.easscan.org",
    tx: "https://polygonscan.com",
  },
};

// The schema definition sygners anchors registrations and signatures with.
export const SCHEMA_DEFINITION =
  "bytes32 documentHash,string action,string email,address subject,bytes32 sigHash";

export const ACTION_REGISTER = "REGISTER";
export const ACTION_SIGN = "SIGN";
export const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

// The only thing that can be tuned: whether the network is touched at all.
// Everything else is a constant, because a verifier with knobs is a verifier
// whose result depends on how you ran it.
export const TOLERANCE_SECONDS = 3600;
export const RPC_TIMEOUT_MS = 20000;

export function options() {
  return { offline: envBool("OFFLINE", false) };
}

// What is required of THIS chain's attestations. Precedence:
// `<VARIABLE>_<chainId>` first, then the variable without a suffix.
export function expectations(chainId) {
  return {
    schemaUid: env(`EAS_SCHEMA_UID_${chainId}`) ?? env("EAS_SCHEMA_UID") ?? null,
    attester: env(`SYGNERS_ATTESTER_${chainId}`) ?? env("SYGNERS_ATTESTER") ?? null,
  };
}

// The configuration of ONE chain, the one the manifest names.
//
// ⚠️ The chain id comes from the manifest and not from the environment, for the
// same reason sygners stores it per document: an operation lives on the network
// where it was anchored, and verifying against today's network would reject
// everything older than a network change.
export function chainFor(chainId) {
  const base = CHAINS[chainId] ?? null;
  const rpcUrl = env(`RPC_URL_${chainId}`) ?? env("RPC_URL") ?? base?.rpc ?? null;
  return {
    chainId,
    name: base?.name ?? `chain ${chainId}`,
    known: Boolean(base),
    // A test network does not carry the same evidentiary weight: its blocks
    // cost nothing to produce and the network can be restarted entirely.
    testnet: Boolean(base?.testnet),
    rpcUrl,
    ownRpc: Boolean(env(`RPC_URL_${chainId}`) || env("RPC_URL")),
    eas: env(`EAS_CONTRACT_ADDRESS_${chainId}`) ?? env("EAS_CONTRACT_ADDRESS") ?? base?.eas ?? null,
    registry:
      env(`SCHEMA_REGISTRY_ADDRESS_${chainId}`) ??
      env("SCHEMA_REGISTRY_ADDRESS") ??
      base?.registry ??
      null,
    attestationUrl: (uid) => (base?.easscan && uid ? `${base.easscan}/attestation/view/${uid}` : null),
    txUrl: (hash) => (base?.tx && hash ? `${base.tx}/tx/${hash}` : null),
  };
}
