// The private keys someone may provide to confirm who signed.
//
// What this proves, exactly: that whoever handed over the `PK_SIGNER…` key
// controls the wallet that produced one of the package's signatures. No more,
// no less. The package already proves —on its own, without a network— that the
// wallet signed the document; the key closes the other end: it ties that wallet
// to the person who gave it to you.
//
// What it does NOT prove: that the person is who they claim to be. A key is
// copied, lent and stolen; possession is not identity. That is what sygners'
// identity verification report is for, and it is another flow.
//
// ⚠️ Two rules, and both are why this lives in its own module:
//
//  1. **The key NEVER signs anything.** Only its public address is derived,
//     which is pure arithmetic and touches the key only to read it. A verifier
//     that could sign with someone else's key is a verifier that can fabricate
//     evidence.
//  2. **The key NEVER leaves here.** Not to the report, not to an error
//     message. The only things that propagate are the derived address and the
//     name of the variable.

import { computeAddress } from "ethers";

// Reads every `PK_SIGNER*` from the environment. The suffix is free:
// `PK_SIGNER1`, `PK_SIGNER_ANA`, anything — it tells you which one failed
// without printing it.
export function providedKeys(environment = process.env) {
  return Object.keys(environment)
    .filter((k) => /^PK_SIGNER/i.test(k))
    .sort()
    .map((name) => ({ name, value: (environment[name] ?? "").trim() }))
    .filter((k) => k.value !== "")
    .map(({ name, value }) => {
      const hex = value.startsWith("0x") ? value : `0x${value}`;
      if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
        // No echo of the value: if someone pasted a key wrong, the error has no
        // business repeating it on screen or in the logs.
        return { name, address: null, error: "does not look like a private key (32 bytes of hex)" };
      }
      try {
        return { name, address: computeAddress(hex), error: null };
      } catch {
        return { name, address: null, error: "is not a valid private key" };
      }
    });
}
