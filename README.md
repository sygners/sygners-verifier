# sygners-verifier

Verifica los archivos de evidencia `.zip` de [sygners](https://github.com/sygners/sygners)
**sin depender de la plataforma**: las únicas fuentes son el zip y un nodo RPC
de la cadena que el propio manifiesto declara.

```bash
npm install
cp .env.example .env     # opcional, pero recomendado
node src/cli.js evidencia.zip
```

Un solo argumento. Todo lo que se ajusta vive en el `.env`.

La salida es un informe estructurado por sujeto: el paquete, el documento, el
anclaje en la cadena y **un bloque por firmante** con todo lo suyo junto —lo que
declara el manifiesto, lo que prueba su firma y lo que dice la cadena—, cada
chequeo con el dato con el que se resolvió.

## Qué comprueba

**Sin tocar la red**

- El zip trae el documento, `constancia.pdf`, `manifiesto.json` y `LEEME.txt`.
- El manifiesto es válido, de formato conocido (`1` o `2`), coherente en fechas
  y con todos los firmantes en `SIGNED`.
- **El SHA-256 del documento es el que declara el manifiesto.**
- **Las firmas EIP-712** (`formato: 2`): de cada firma cruda se recupera quién
  la produjo y tiene que dar la wallet declarada; el mensaje firmado tiene que
  decir el hash de *este* documento, *esta* operación, ese correo y la
  declaración de sygners. El dominio EIP-712 del paquete se verifica, no se usa
  a ciegas.
- Que la evidencia no sea **simulada**: sin cadena configurada, sygners genera
  UIDs deterministas que se pueden recalcular acá.

**Contra la cadena**

- El nodo declara el mismo `chainId` que el manifiesto, o no se coteja nada.
- El **registro** existe, no está revocado, y dice el mismo hash, `REGISTER`, y
  el correo y la wallet del emisor.
- **Cada firma** existe, dice `SIGN`, sobre el mismo hash, con el correo y la
  wallet de ese firmante, referenciando (`refUID`) al registro.
- **La huella anclada es la de la firma que trae el paquete**
  (`keccak256(firma) == sigHash`): ata la firma verificable a lo que quedó en
  la cadena.
- El schema on-chain es textualmente el de sygners, leído del SchemaRegistry.
- Las transacciones existen, salieron bien y fueron al contrato de EAS.
- Si configuraste `SYGNERS_ATTESTER` y `EAS_SCHEMA_UID`, que sean esos.
- Si la cadena es una red de prueba, lo avisa.

**Si aportás claves privadas** (`PK_SIGNER*`)

De cada una se deriva la dirección y se busca entre las wallets del paquete.
Acredita **control de la wallet, no identidad**. La clave nunca firma nada ni
aparece en la salida.

## Veredictos

| veredicto | salida | |
|---|---|---|
| `VERIFICA` | 0 | el documento es el anclado y la cadena lo confirma |
| `VERIFICA PARCIALMENTE` | 0 | con `SIN_CADENA=true`: sin cotejar contra la red |
| `EVIDENCIA SIMULADA` | 1 | salió de una instancia sin cadena: no prueba nada |
| `NO VERIFICA` | 1 | falló un chequeo bloqueante |

## Configuración

Todo en `.env` (ver `.env.example`): `RPC_URL_<chainId>`, `EAS_SCHEMA_UID`,
`SYGNERS_ATTESTER[_<chainId>]`, `PK_SIGNER*`, `SIN_CADENA` y, para cadenas que
no estén en la tabla, `EAS_CONTRACT_ADDRESS_<chainId>` y
`SCHEMA_REGISTRY_ADDRESS_<chainId>`.

Para la sygners de producción alcanza con:

```bash
RPC_URL_10=https://mainnet.optimism.io
RPC_URL_11155420=https://sepolia.optimism.io
EAS_SCHEMA_UID=0xcc6fea68545dd0ab10a1cd630ccf0f63cba74c819c3b334a22d2d1e15468dc5f
SYGNERS_ATTESTER_10=0x8ad3446c381c3df420Bba1A1329F71484e7a31D8
```

## Desarrollo

```bash
npm run fixtures   # arma pruebas/fixtures/*.zip
npm run prueba     # 54 chequeos, sin red y sin sygners (nodo JSON-RPC falso)
```

`src/verificar.js` tiene los chequeos; `src/eas.js` lee la cadena;
`src/firma.js` las firmas EIP-712; `src/claves.js` las claves aportadas.
Dependencias: `ethers` y `fflate`.
