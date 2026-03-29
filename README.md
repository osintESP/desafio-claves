# key_exchange — Desafío Técnico MercadoPago

Solución al desafío de intercambio de claves criptográficas.
Implementa los tres objetivos del enunciado más el bonus DUKPT.

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/osintESP/desafio-claves.git
cd desafio-claves
```

### 2. Crear y activar el entorno virtual

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows:**
```bat
python -m venv .venv
.venv\Scripts\activate
```

### 3. Instalar dependencias

**Mac / Linux:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows:**
```bat
pip install --upgrade pip
pip install -r requirements.txt
```

> El `pip install --upgrade pip` evita el warning `WARNING: You are using pip version X...` que aparece al instalar con versiones antiguas de pip.

---

## Uso

### Modo interactivo (recomendado)

Ejecutar sin argumentos lanza un asistente que solicita cada valor por pantalla.
Compatible con Windows y Mac:

**Mac / Linux:**
```bash
python3 -m key_exchange
```

**Windows:**
```bat
python -m key_exchange
```

El programa pide cada valor de a uno, con una línea de entrada por campo:

```
============================================================
  Intercambio de claves criptográficas — Modo interactivo
============================================================

Seleccione una operación:
  1) export-pek  — Generar y exportar una PEK en key block TR-31
  2) import-bdk  — Importar y validar la BDK desde un key block TR-31

Opción (1 o 2): 2

--- Componentes de la KEK ---
  KEK Componente 1  (hex o ruta a archivo): db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6
  KEK Componente 2  (hex o ruta a archivo): 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7
  KEK KCV  (6 caracteres hex): F74B90

--- Parámetros de import-bdk ---
  BDK Key Block  (hex o ruta a archivo): bdk_keyblock.txt
  BDK KCV  (6 caracteres hex): EABBDC
  KSN (DUKPT)  (20 chars hex, 10 bytes) [Enter para omitir]: 729C77361E9A51E000F2
  Ciphertext a descifrar  (hex, múltiplo de 8 bytes) [Enter para omitir]: FCC832A91953151148E86A01BE9420AC
```

> **Tip:** El key block TR-31 de la BDK es muy largo para pegarlo directamente.
> Guardalo en un archivo de texto primero:
>
> **Mac / Linux:**
> ```bash
> echo "D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76" > bdk_keyblock.txt
> ```
> **Windows:**
> ```bat
> echo D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 > bdk_keyblock.txt
> ```
> Luego cuando el programa pida el BDK Key Block, ingresá: `bdk_keyblock.txt`

---

### Modo CLI (argumentos)

#### Exportar la PEK

**Mac / Linux:**
```bash
python3 -m key_exchange export-pek \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --out <ruta de salida>
```

**Windows:**
```bat
python -m key_exchange export-pek --kek-component-1 <hex o ruta> --kek-component-2 <hex o ruta> --kek-kcv <KCV esperado> --out <ruta de salida>
```

#### Importar la BDK

**Mac / Linux:**
```bash
python3 -m key_exchange import-bdk \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --bdk-keyblock <key block o ruta> \
  --bdk-kcv <KCV esperado>
```

**Windows:**
```bat
python -m key_exchange import-bdk --kek-component-1 <hex o ruta> --kek-component-2 <hex o ruta> --kek-kcv <KCV esperado> --bdk-keyblock <key block o ruta> --bdk-kcv <KCV esperado>
```

---

## Resultados con los datos del enunciado

### export-pek

```
[*] Ensamblando KEK...
[+] KEK válida. KCV=F74B90
[*] Generando PEK aleatoria (AES-256)...
[+] PEK generada. KCV=20B583
[*] Envolviendo PEK en key block TR-31...
[+] Key block guardado en: pek_keyblock.txt
[+] KCV de la PEK: 20B583
```

Key block TR-31 generado:
```
D0144P0AE00S000083F2B29042069AB0A388BD4D5EDC0B7E540A05F295BF4D2E4F522A48B7CCB8C51777EE05F30DBF3445F2CDC669E0F22C2754DFDC7C4FCBBDB71CCB088C476437
```

---

### import-bdk + bonus DUKPT

```
[*] Ensamblando KEK...
[+] KEK válida. KCV=F74B90
[*] Desenvolviendo key block TR-31 de la BDK...
[+] BDK desenvuelta: 128 bits
[*] Verificando KCV de la BDK...
[+] BDK válida. KCV=EABBDC

[*] Ejecutando bonus DUKPT...
[+] KSN       : 729C77361E9A51E000F2
[+] IPEK      : DB833E79B68B868C285534462F0099B5
[+] Future Key: F0BBF26A9B1D48220ED642709E5C4454
[+] Plaintext : 4D454C495F526F636B73210000000000
```

**Mensaje descifrado: `MELI_Rocks!`**

---

## Tests

```bash
python3 -m pytest tests/ -v      # Mac / Linux
python -m pytest tests/ -v       # Windows
```

67 casos de prueba: vectores reales del enunciado + suite adversarial exhaustiva.

---

## Estructura del proyecto

```
key_exchange/
├── __init__.py      # marcador de módulo
├── __main__.py      # CLI: modo interactivo + argparse (export-pek / import-bdk)
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

**Los mensajes de error no revelan información sensible.**
`verify_kcv` solo informa que el KCV no coincide, sin exponer el valor calculado
ni el esperado. Esto evita que un atacante use los mensajes de error para inferir
información sobre las claves.

**Validación de tipos y tamaños en todas las funciones criptográficas.**
Cada función valida el tipo (`bytes`/`str`) y el tamaño de sus argumentos antes
de operar. Las excepciones de librerías externas (`dukpt`, `cryptography`) se
capturan y se relanza como `ValueError` con mensajes sin información sensible.
Los valores `None`, strings vacíos, archivos vacíos y tamaños de clave inválidos
son rechazados explícitamente en la frontera de cada módulo.

---

## Respuestas a las preguntas teóricas

**1. ¿Podrían enviarse los dos componentes de la KEK por el mismo canal?**
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
| `pytest` | 7.0.0 | Tests |
