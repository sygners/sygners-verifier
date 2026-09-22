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

La salida es un informe estructurado por sujeto, con cada chequeo acompañado del
dato con el que se resolvió:

```
 Veredicto    VERIFICA
 Chequeos     42 ok · 0 fallas · 2 avisos · 0 omitidos

 1. PAQUETE                      piezas del zip y forma del manifiesto
 2. DOCUMENTO                    el SHA-256 y lo que el manifiesto declara
 3. ANCLAJE EN LA CADENA         registro, schema, atestador, transacción
 4. ESQUEMA DE FIRMA (EIP-712)   dominio y tipos
 5. FIRMANTE 1 DE N — email      todo lo suyo junto: manifiesto, firma y cadena
 6. CLAVES PRIVADAS              qué confirmó cada una, o que no se aportaron
 RESULTADO                       veredicto, fallas y avisos
```

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

**Quién controla cada wallet** (`PK_SIGNER*`, opcional)

Si te entregan la clave privada de un firmante, de cada una se deriva la
dirección y se busca entre las wallets del paquete. La clave nunca firma nada ni
aparece en la salida, y acredita **control de la wallet, no identidad**.

Si no se aporta ninguna, el informe **lo avisa** y nombra a los firmantes que
quedaron sin confirmar: el paquete prueba que ciertas wallets firmaron, no quién
las controla hoy, y un `VERIFICA` a secas se lee como si probara las dos cosas.

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

Cadenas conocidas: Ethereum (1), Sepolia (11155111), OP Mainnet (10), OP Sepolia
(11155420), Base (8453), Base Sepolia (84532), Arbitrum One (42161) y
Polygon (137). Para la sygners de producción alcanza con:

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
