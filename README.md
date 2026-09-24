# sygners-verifier

Verifies [sygners](https://github.com/sygners/sygners) `.zip` evidence files
**without depending on the platform**: the only sources are the zip and an RPC
node of the chain the manifest itself declares.

```bash
npm install
cp .env.example .env     # optional, but recommended
node src/cli.js evidence.zip
```

One argument. Everything that can be tuned lives in the `.env`.

The output is a report structured by subject, each check accompanied by the
value it was resolved with:

```
 Verdict      VERIFIED
 Checks       42 ok · 0 failed · 2 warnings · 0 skipped

 1. PACKAGE                      zip pieces and manifest shape
 2. DOCUMENT                     the SHA-256 and what the manifest declares
 3. ANCHORING ON CHAIN           registration, schema, attester, transaction
 4. SIGNING SCHEME (EIP-712)     domain and types
 5. SIGNER 1 OF N — email        everything about them: manifest, signature, chain
 6. SIGNERS' PRIVATE KEYS        what each one confirmed, or that none were given
 RESULT                          verdict, failures and warnings
```

## What it checks

**Without touching the network**

- The zip carries the document, `constancia.pdf`, `manifiesto.json` and
  `LEEME.txt`.
- The manifest is valid, of a known format (`1` or `2`), coherent in its dates
  and with every signer `SIGNED`.
- **The document's SHA-256 is the one the manifest declares.**
- **The EIP-712 signatures** (`formato: 2`): from each raw signature it recovers
  who produced it, which has to be the declared wallet; the signed message has
  to state the hash of *this* document, *this* operation, that email and
  sygners' statement. The package's EIP-712 domain is verified, not used blindly.
- That the evidence is not **mock**: with no chain configured, sygners generates
  deterministic UIDs that can be recomputed here.

**Against the chain**

- The node declares the same `chainId` as the manifest, or nothing is
  cross-checked.
- The **registration** exists, is not revoked, and states the same hash,
  `REGISTER`, and the issuer's email and wallet.
- **Each signature** exists, says `SIGN`, over the same hash, with that signer's
  email and wallet, referencing (`refUID`) the registration.
- **The anchored fingerprint is the one of the signature in the package**
  (`keccak256(signature) == sigHash`): it ties the verifiable signature to what
  was written on chain.
- The on-chain schema is textually sygners', read from the SchemaRegistry.
- The transactions exist, succeeded and went to the EAS contract.
- If you configured `SYGNERS_ATTESTER` and `EAS_SCHEMA_UID`, that they are those.
- If the chain is a test network, it warns.

**Who controls each wallet** (`PK_SIGNER*`, optional)

If you are handed a signer's private key, each one's address is derived and
looked up among the package's wallets. The key never signs anything and never
appears in the output, and it establishes **control of the wallet, not
identity**.

If none is provided, the report **says so** and names the signers left
unconfirmed: the package proves that certain wallets signed, not who controls
them today, and a bare `VERIFIED` reads as if it proved both.

## Verdicts

| verdict | exit | |
|---|---|---|
| `VERIFIED` | 0 | the document is the anchored one and the chain confirms it |
| `PARTIALLY VERIFIED` | 0 | with `OFFLINE=true`: not cross-checked against the network |
| `MOCK EVIDENCE` | 1 | came from an instance with no chain: it proves nothing |
| `DOES NOT VERIFY` | 1 | a blocking check failed |

## Configuration

All in `.env` (see `.env.example`): `RPC_URL_<chainId>`, `EAS_SCHEMA_UID`,
`SYGNERS_ATTESTER[_<chainId>]`, `PK_SIGNER*`, `OFFLINE` and, for chains not in
the table, `EAS_CONTRACT_ADDRESS_<chainId>` and
`SCHEMA_REGISTRY_ADDRESS_<chainId>`.

Known chains: Ethereum (1), Sepolia (11155111), OP Mainnet (10), OP Sepolia
(11155420), Base (8453), Base Sepolia (84532), Arbitrum One (42161) and
Polygon (137). For sygners production this is enough:

```bash
RPC_URL_10=https://mainnet.optimism.io
RPC_URL_11155420=https://sepolia.optimism.io
EAS_SCHEMA_UID=0xcc6fea68545dd0ab10a1cd630ccf0f63cba74c819c3b334a22d2d1e15468dc5f
SYGNERS_ATTESTER_10=0x8ad3446c381c3df420Bba1A1329F71484e7a31D8
```

## Development

```bash
npm run fixtures   # builds tests/fixtures/*.zip
npm test           # 55 checks, no network and no sygners (fake JSON-RPC node)
```

`src/verify.js` holds the checks; `src/eas.js` reads the chain;
`src/signature.js` the EIP-712 signatures; `src/keys.js` the provided keys.
Dependencies: `ethers` and `fflate`.

> The manifest's field names (`documento`, `firmantes`, `cadena`…) and the
> signed statement stay in Spanish everywhere in the code: they are data written
> by sygners, not prose. Renaming them would stop reading the file, and
> translating the statement would break every signature.
