# key_exchange — Desafío Técnico MercadoPago

Solución al desafío de intercambio de claves criptográficas.
Implementa los tres objetivos del enunciado más el bonus DUKPT.

---

## Instalación

```bash
pip install -r requirements.txt
```

O como paquete instalable (habilita el comando `key-exchange` directamente):

```bash
pip install -e .
```

---

## Uso

### Exportar la PEK

Genera una PEK aleatoria y la entrega envuelta en un key block TR-31:

```bash
python -m key_exchange export-pek \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --out <ruta de salida>
```

**Salida:** key block TR-31 de la PEK + KCV para verificación.

---

### Importar la BDK

Desenvuelve y valida el key block TR-31 de la BDK:

```bash
python -m key_exchange import-bdk \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --bdk-keyblock <key block o ruta> \
  --bdk-kcv <KCV esperado>
```

**Salida:** BDK validada + resultado del bonus DUKPT.

---

## Ejemplo con los datos del enunciado

```bash
python -m key_exchange import-bdk \
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 \
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 \
  --kek-kcv F74B90 \
  --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 \
  --bdk-kcv EABBDC
```

```bash
python -m key_exchange export-pek \
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 \
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 \
  --kek-kcv F74B90 \
  --out pek_keyblock.txt
```

---

## Tests

```bash
python -m pytest tests/ -v
```

33 casos de prueba que usan los vectores reales del enunciado (componentes, KCV, key block BDK).

---

## Estructura del proyecto

```
key_exchange/
├── __init__.py      # marcador de módulo
├── __main__.py      # CLI: argparse, subcomandos export-pek e import-bdk
├── kek.py           # ensamblado de KEK por XOR y validación KCV
├── kcv.py           # cálculo de KCV: CMAC-KCV (AES) y KCV legacy (3DES)
├── keyblock.py      # wrap y unwrap de key blocks TR-31 usando psec
└── dukpt.py         # bonus: derivación DUKPT y descifrado 3DES-ECB
tests/
├── test_kcv.py      # KCV CMAC y legacy, verify_kcv
├── test_kek.py      # ensamblado KEK, carga de componentes
├── test_keyblock.py # wrap/unwrap TR-31, roundtrip
├── test_dukpt.py    # IPEK, future key, descifrado
└── test_validation.py  # validación de entradas hex del CLI
```

---

## Flujo de operación

```
Componente 1  ─┐
               ├─ XOR ─► KEK ─► validar KCV (CMAC-KCV)
Componente 2  ─┘
                              │
                              ├─ unwrap TR-31 ─► BDK ─► validar KCV (3DES-ECB)
                              │                          │
                              │                          └─ [BONUS] BDK + KSN
                              │                              ─► IPEK ─► future key
                              │                              ─► descifrar 3DES-ECB
                              │
                              └─ wrap TR-31 ─► PEK (nueva) ─► KCV (CMAC-KCV)
```

---

## Decisiones de diseño

**`kcv.py` separado y reutilizable.**
La KEK (AES-256) usa CMAC-KCV. La BDK (3DES) usa KCV legacy (3DES-ECB sobre 8 bytes en cero).
Separar este módulo evita duplicar lógica y centraliza la verificación.

**Validación antes de continuar.**
Cada KCV se verifica inmediatamente tras ensamblar la clave. Si falla, el programa
se detiene con un mensaje claro antes de intentar cualquier operación criptográfica
sobre una clave potencialmente incorrecta.

**`os.urandom()` para la PEK.**
Usa el generador criptográficamente seguro del sistema operativo (CSPRNG).
No se usa `random` porque es un generador estadístico, no criptográfico.

**`psec` para TR-31.**
La librería verifica el MAC del key block antes de descifrar. Esto implementa
el principio de *fail fast*: se rechaza un bloque manipulado antes de gastar
recursos en descifrarlo.

**Comparación KCV en tiempo constante.**
`verify_kcv` usa `hmac.compare_digest` en lugar de `==` para evitar que un
atacante pueda inferir cuántos bytes coinciden midiendo el tiempo de respuesta.

**Validación de entradas en la frontera del sistema.**
El CLI valida formato hex, paridad de caracteres, longitudes esperadas (KCV = 3 bytes,
KSN = 10 bytes) y múltiplo de bloque (ciphertext 3DES) antes de ejecutar cualquier
operación criptográfica, devolviendo mensajes de error claros al usuario.

---

## Respuestas a las preguntas teóricas

**1. ¿Podrían enviarse los dos componentes por el mismo canal?**
No. Si el canal es comprometido, el atacante obtiene ambos componentes y puede
reconstruir la KEK con XOR. El valor de seguridad del split depende de que los
canales sean independientes: comprometer uno no debe comprometer el otro.

**2. ¿Qué método alternativo para entregar la KEK sin que viaje entera?**
Opciones: (a) Shamir Secret Sharing — esquema matemático donde se necesitan k de n
partes para reconstruir el secreto. (b) Key wrapping asimétrico — cifrar la KEK
con la clave pública del HSM de destino; solo ese HSM puede descifrarla.
(c) Tres componentes XOR con quórum k=2. (d) Diffie-Hellman para derivar un
secreto compartido sin que este viaje por ningún medio.

**3. Si un custodio es comprometido, ¿queda comprometida la KEK?**
Con un solo componente: no. Un componente es indistinguible de datos aleatorios
sin el otro; todas las KEKs posibles son igualmente probables para el atacante.
Con dos componentes comprometidos: sí, la KEK se reconstruye trivialmente con XOR.
Por eso el dual control exige que los custodios sean completamente independientes.

---

## Dependencias

| Librería | Versión mínima | Uso |
|---|---|---|
| `cryptography` | 42.0.0 | AES-CMAC para KCV, 3DES-ECB para KCV legacy y bonus |
| `psec` | 1.0.0 | Wrap y unwrap de key blocks TR-31 (ANSI X9.143) |
| `dukpt` | 1.0.0 | Derivación IPEK y future key para el bonus |
| `bitstring` | — | Manejo de BitArray para la API de dukpt |
