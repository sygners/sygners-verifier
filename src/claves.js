// Las claves privadas que alguien aporte para confirmar quién firmó.
//
// Qué prueba esto, exactamente: que quien entregó la clave `PK_SIGNER…`
// controla la wallet que produjo una de las firmas del paquete. Ni más ni
// menos. El paquete ya prueba —solo, sin red— que esa wallet firmó el
// documento; la clave cierra el otro extremo: ata esa wallet a quien te la dio.
//
// Qué NO prueba: que esa persona sea quien dice ser. Una clave se copia, se
// presta y se roba; posesión no es identidad. Para eso está el informe de
// verificación de identidad de sygners, que es otro flujo.
//
// ⚠️ Dos reglas, y las dos son la razón de que esto viva en su propio módulo:
//
//  1. **La clave NUNCA firma nada.** Solo se deriva su dirección pública, que
//     es una cuenta de matemática pura y no toca la clave más que para leerla.
//     Un verificador que firmara con una clave ajena sería un verificador que
//     puede fabricar evidencia.
//  2. **La clave NUNCA sale de acá.** Ni al informe, ni al JSON, ni a un
//     mensaje de error. Lo único que se propaga es la dirección derivada y el
//     nombre de la variable.

import { computeAddress } from "ethers";

// Lee todas las `PK_SIGNER*` del entorno. El sufijo es libre: `PK_SIGNER1`,
// `PK_SIGNER_ANA`, lo que sea — sirve para saber cuál falló sin imprimirla.
export function clavesAportadas(entorno = process.env) {
  return Object.keys(entorno)
    .filter((k) => /^PK_SIGNER/i.test(k))
    .sort()
    .map((nombre) => ({ nombre, valor: (entorno[nombre] ?? "").trim() }))
    .filter((c) => c.valor !== "")
    .map(({ nombre, valor }) => {
      const hex = valor.startsWith("0x") ? valor : `0x${valor}`;
      if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
        // Sin eco del valor: si alguien pegó mal una clave, el error no tiene
        // por qué repetirla en pantalla ni en los logs.
        return { nombre, direccion: null, error: "no tiene forma de clave privada (32 bytes en hex)" };
      }
      try {
        return { nombre, direccion: computeAddress(hex), error: null };
      } catch {
        return { nombre, direccion: null, error: "no es una clave privada válida" };
      }
    });
}
