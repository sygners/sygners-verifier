# sygners-verifier

Verificador independiente de los archivos de evidencia `.zip` que entrega
[sygners](https://github.com/sygners/sygners).

**No depende de la plataforma.** No hay una sola llamada a sygners en todo el
programa. Las únicas dos fuentes son el `.zip` que te pasaron y un nodo RPC de
la cadena que el propio manifiesto declara. Esa es toda la razón de existir de
este repo: una evidencia que necesite que su emisor siga en línea para poder
comprobarse no es evidencia.

```bash
npm install
node src/cli.js sygners-evidencia-contrato.zip
```

---

## Qué hay adentro de un paquete de evidencia

Cuatro archivos, tal como los arma `src/lib/archivo-evidencia.ts` de sygners:

| archivo | qué es |
|---|---|
| `<documento>` | el documento original, tal como se firmó (el nombre es el suyo) |
| `constancia.pdf` | la constancia de firma: hashes, wallets, fechas |
| `manifiesto.json` | los mismos hechos en JSON, armados por el servidor; desde el formato 2, también la firma cruda de cada firmante |
| `LEEME.txt` | las instrucciones en prosa, con el hash escrito adentro |

## Qué comprueba este verificador

**Sin red (siempre):**

1. El `.zip` abre y trae las cuatro piezas, con un solo documento adentro.
2. El manifiesto es JSON válido, de formato conocido (`formato: 1` o `2`), con
   todos sus campos, fechas coherentes y todos los firmantes en `SIGNED`.
3. **El SHA-256 del documento es el que declara el manifiesto.** Es *el*
   chequeo: si falla, el archivo que viene adentro no es el que se firmó.
4. El tamaño, el nombre y el hash repetido en `LEEME.txt` concuerdan.
5. **Que la evidencia no sea simulada.** Cuando a sygners le falta el relayer,
   el RPC o el UID del schema, no ancla nada: genera UIDs deterministas
   (`keccak256("uid:register:<id>")`) para que el flujo local siga siendo
   trazable. Un paquete así se ve idéntico a uno real — salvo que sus UIDs se
   pueden **recalcular**, y eso es lo que se hace acá, sin tocar la red.
6. **Las firmas EIP-712, recuperando la dirección** (manifiesto `formato: 2` en
   adelante): de cada firma cruda se recupera quién la produjo y tiene que dar
   la wallet declarada. Además, el mensaje firmado tiene que decir el hash de
   *este* documento, *esta* operación, el correo de *ese* firmante y la
   declaración de sygners, y `keccak256(firma)` tiene que dar la huella
   declarada. **Esto no necesita la cadena**: es la única parte de la evidencia
   que se sostiene sola, sin creerle a nadie.
7. El dominio y los tipos EIP-712 que trae el paquete son los de sygners para la
   cadena del documento. Se verifican, no se usan a ciegas: un dominio elegido a
   medida haría que una firma que esa wallet hizo en otra app recupere limpia y
   parezca una firma de este documento. La recuperación corre siempre con el
   dominio canónico.

**Contra la cadena (por RPC, salvo `--sin-cadena`):**

8. El nodo declara el mismo `chainId` que el manifiesto, o no se coteja nada.
9. La atestación del **registro** existe, no está revocada ni vencida, y sus
   datos decodificados con el schema de sygners dicen: el mismo hash de
   documento, `action = REGISTER`, el correo y la wallet del emisor.
10. La atestación de **cada firma** existe, dice `action = SIGN`, sobre el mismo
    hash de documento, con el correo y la wallet de ese firmante,
    **referenciando (`refUID`) al registro** y bajo el mismo schema.
11. **La huella anclada es la de la firma que trae el paquete**
    (`keccak256(firma) == sigHash` on-chain). Es el nudo entre las dos mitades:
    ata la firma que se puede verificar sola a lo que quedó escrito en la
    cadena. Sin firma cruda, solo se comprueba que el `sigHash` no venga en cero.
12. El schema on-chain es, textualmente,
    `bytes32 documentHash,string action,string email,address subject,bytes32 sigHash`
    — leído del SchemaRegistry de esa cadena, no asumido.
13. Las transacciones existen, salieron bien (`status = 1`) y fueron al
    contrato de EAS.
14. La fecha que declara el manifiesto y la del bloque están cerca (aviso).
15. Opcional y lo más fuerte que podés exigir: que el **atestador** y el **UID
    del schema** sean los que vos esperás (`SYGNERS_ATTESTER`, `EAS_SCHEMA_UID`).

## Formatos de manifiesto

| formato | desde | qué trae de más |
|---|---|---|
| `1` | el día uno | los hechos de la operación y los identificadores on-chain |
| `2` | 22/09/2026 | `eip712` (dominio y tipos) y, por firmante, `mensaje` + `firma` + `sigHash` |

Los dos se verifican. Un formato más nuevo que `2` corre igual, con un aviso de
que puede haber campos que este verificador no mira.

> **Las dos wallets del manifiesto son distintas a propósito.** `emisor.wallet`
> es la del **registro** on-chain: identifica a quien creó la operación y no
> firma nada, así que no se recupera de ninguna firma. Las que se verifican
> contra las firmas son las de `firmantes[].wallet`. Cuando quien emite además
> firma, aparece en los dos lugares con direcciones distintas — el informe lo
> aclara cuando pasa.

## Veredictos y códigos de salida

| veredicto | salida | significa |
|---|---|---|
| `VERIFICA` | 0 | el documento es el anclado y la cadena dice lo que el manifiesto dice |
| `VERIFICA PARCIALMENTE (sin cadena)` | 0 | el documento es el del manifiesto y, en formato 2, las firmas se verificaron; no se cotejó contra la red |
| `EVIDENCIA SIMULADA` | 1 | salió de una instancia sin cadena: no prueba nada frente a un tercero |
| `NO VERIFICA` | 1 | falló al menos un chequeo bloqueante |

## Uso

```bash
node src/cli.js <archivo.zip> [opciones]

  --sin-cadena          solo chequeos offline (veredicto parcial)
  --json                informe en JSON por stdout
  --extraer <carpeta>   además, escribe el documento, la constancia y el manifiesto
  --rpc <url>           RPC a usar, por encima del entorno
  --schema-uid <0x…>    UID de schema EAS exigido
  --attester <0x…>      dirección que tuvo que anclar
  --sin-tx              no pedir los recibos de transacción
  --estricto            los avisos también hacen fallar
  --tolerancia <seg>    diferencia admitida entre la fecha declarada y la del bloque
  --env <archivo>       .env a usar
```

Instalado global (`npm link` o `npm i -g .`) queda como `sygners-verificar`.

Para automatizar:

```bash
node src/cli.js evidencia.zip --json | jq -r '.veredicto, (.chequeos[] | select(.estado=="falla") | .titulo)'
```

## Variables de entorno

Todas son opcionales: el verificador corre sin `.env`. Copiá `.env.example` a
`.env` y completá lo que quieras. Lo que ya esté en el entorno le gana al
archivo, así que `RPC_URL_11155111=... node src/cli.js …` también funciona.

| variable | para qué | default |
|---|---|---|
| `RPC_URL_<chainId>` | el nodo de esa cadena; es el que manda | nodo público de publicnode.com |
| `RPC_URL` | comodín, para cualquier cadena sin el anterior | — |
| `EAS_CONTRACT_ADDRESS_<chainId>` | contrato EAS de esa cadena | el oficial (ver `src/config.js`) |
| `SCHEMA_REGISTRY_ADDRESS_<chainId>` | SchemaRegistry de esa cadena | el oficial |
| `EAS_CONTRACT_ADDRESS` / `SCHEMA_REGISTRY_ADDRESS` | comodines | — |
| `EAS_SCHEMA_UID[_<chainId>]` | **exige** que las atestaciones usen ese schema | sin exigir |
| `SYGNERS_ATTESTER[_<chainId>]` | **exige** que las haya anclado esa dirección | sin exigir |
| `SYGNERS_SCHEMA_DEFINICION` | texto del schema esperado | el de sygners |
| `SIN_CADENA` | `true` → solo chequeos offline | `false` |
| `VERIFICAR_TX` | pedir los recibos de transacción | `true` |
| `TOLERANCIA_FECHA_SEGUNDOS` | fecha declarada vs. fecha del bloque | `3600` |
| `RPC_TIMEOUT_MS` | timeout de cada pedido al RPC | `20000` |
| `ESTRICTO` | los avisos también hacen fallar | `false` |

Cadenas con tabla propia: Ethereum (1), Ethereum Sepolia (11155111, el default
del código de sygners), Base (8453), Base Sepolia (84532), **OP Mainnet (10,
donde ancla la sygners de producción)**, **OP Sepolia (11155420, el entorno de
prueba)**, Arbitrum One (42161), Polygon (137). Cualquier otra funciona
configurando las tres variables `_<chainId>`.

Las expectativas (`EAS_SCHEMA_UID`, `SYGNERS_ATTESTER`) también aceptan sufijo
de cadena, y el sufijo gana. Sirve para tener producción y preproducción
configuradas a la vez: cada entorno ancla con su propio relayer, y un valor
suelto haría fallar a los paquetes del otro por una diferencia esperada. El UID
del schema, en cambio, sale de la definición del schema y suele ser el mismo en
todas las cadenas.

Sobre las redes de prueba: el verificador comprueba el anclaje igual, pero avisa.
Una testnet no cuesta nada de producir y puede reiniciarse entera, así que como
prueba de que un documento existía en una fecha no vale lo mismo que una red de
producción.

> ⚠️ El `.env` de sygners usa `EAS_CONTRACT_ADDRESS=0x42…21` como default, que
> es el predeploy de las cadenas OP-stack. En Sepolia el contrato es otro. Acá
> cada cadena usa el suyo: **no copies el `.env` de la plataforma**.

## Verificar evidencia de la sygners de producción

La plataforma ancla hoy en **OP Mainnet (chainId 10)**, y su entorno de prueba
en **OP Sepolia (11155420)**. Con esto en tu `.env` alcanza para los dos:

```bash
RPC_URL_10=https://mainnet.optimism.io
RPC_URL_11155420=https://sepolia.optimism.io
EAS_SCHEMA_UID=0xcc6fea68545dd0ab10a1cd630ccf0f63cba74c819c3b334a22d2d1e15468dc5f
SYGNERS_ATTESTER_10=0x8ad3446c381c3df420Bba1A1329F71484e7a31D8
# SYGNERS_ATTESTER_11155420=…  ← el relayer de preproducción, cuando lo confirmes
```

Los tres están comprobados contra la cadena: el UID existe en el SchemaRegistry
de OP y su definición es exactamente la de sygners; el atestador es el que firma
todas las atestaciones de ese schema. Ninguno es secreto — la red es pública, el
schema está publicado y el atestador figura en cada atestación.

`EAS_CONTRACT_ADDRESS_10` y `SCHEMA_REGISTRY_ADDRESS_10` no hacen falta: los
defaults del verificador para OP (`0x42…21` y `0x42…20`) ya son los correctos.

> **El verificador nunca necesita la clave privada del relayer.** Lee la cadena,
> no escribe en ella. Si un `.env` de verificación tiene una clave privada
> adentro, es una clave privada de más en el disco.

### Por qué esas dos variables importan

Sin `EAS_SCHEMA_UID` y `SYGNERS_ATTESTER` el informe prueba que el documento es
el que se ancló y que las atestaciones están donde el manifiesto dice — pero no
que las haya anclado sygners: cualquiera puede escribir una atestación con
cualquier contenido. Con ellas, una atestación bajo otro schema o anclada por
otra wallet se rechaza. Conseguilas una vez, de una fuente que no sea el propio
paquete que estás verificando, y guardalas: son el ancla de confianza.

## Comprobación a mano, sin este programa

Todo lo de arriba se puede hacer con `unzip`, `shasum` y un explorador. El
verificador solo lo hace completo y sin olvidarse de nada:

```bash
unzip -o evidencia.zip -d evidencia/
shasum -a 256 "evidencia/contrato.txt"        # tiene que dar el hash del manifiesto
jq -r '.documento.hash, .cadena.registroUid' evidencia/manifiesto.json
# y buscar ese UID en https://optimism.easscan.org/attestation/view/<uid>
```

## Desarrollo

```bash
npm run fixtures   # arma pruebas/fixtures/*.zip (simulada, manipulada, inventada)
npm run prueba     # corre la prueba: offline + camino positivo y negativos
                   # contra un nodo JSON-RPC falso. No necesita red ni sygners.
```

Estructura:

```
src/cli.js         línea de comandos, códigos de salida
src/verificar.js   los chequeos y el veredicto
src/eas.js         lectura de EAS por RPC (getAttestation, getSchema, recibos)
src/simulado.js    detección de los UIDs del modo sin cadena
src/zip.js         apertura del paquete (nada tira por estar incompleto)
src/config.js      cadenas, contratos, RPC y opciones
src/informe.js     el informe en pantalla y en JSON
src/hash.js        SHA-256, igual que en la plataforma
src/env.js         lectura del .env, sin dependencias
```

Dependencias: `ethers` (leer la cadena) y `fflate` (abrir el zip). Nada más, a
propósito: esto tiene que poder instalarse dentro de diez años.
