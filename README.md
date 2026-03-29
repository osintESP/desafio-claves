# Desafío Técnico MercadoPago

Solución al desafío de intercambio de claves criptográficas.
Implementa los tres objetivos del enunciado más el bonus DUKPT.

> Desarrollado con asistencia de [Claude Code](https://claude.ai/code) como herramienta de apoyo.

---

## Instalación

```bash
git clone https://github.com/osintESP/desafio-claves.git
cd desafio-claves
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Uso

### Modo interactivo

```bash
python3 -m key_exchange
```

### Exportar PEK

```bash
python3 -m key_exchange export-pek \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --out <ruta de salida>
```

### Importar BDK

```bash
python3 -m key_exchange import-bdk \
  --kek-component-1 <hex o ruta> \
  --kek-component-2 <hex o ruta> \
  --kek-kcv <KCV esperado> \
  --bdk-keyblock <key block o ruta> \
  --bdk-kcv <KCV esperado>
```

> **Tip:** Si el key block TR-31 de la BDK es muy largo, guardalo en un archivo:
> ```bash
> echo "D0112B0TX00E0000..." > bdk_keyblock.txt
> ```
> y pasá la ruta como argumento.

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
python3 -m pytest tests/ -v
```

67 casos de prueba: vectores reales del enunciado + validación exhaustiva de entradas.

---

## Estructura

```
key_exchange/
├── __main__.py      # CLI: modo interactivo + argparse
├── kek.py           # ensamblado KEK por XOR y validación KCV
├── kcv.py           # CMAC-KCV (AES) y KCV legacy (3DES)
├── keyblock.py      # wrap/unwrap TR-31
└── dukpt.py         # bonus DUKPT: IPEK, future key, descifrado
tests/
├── test_kcv.py
├── test_kek.py
├── test_keyblock.py
├── test_dukpt.py
└── test_validation.py
```

---

## Respuestas teóricas

**1. ¿Podrían enviarse los dos componentes por el mismo canal?**
No. Si el canal es comprometido, el atacante obtiene ambos y reconstruye la KEK con XOR. El valor del split depende de canales independientes.

**2. ¿Método alternativo para entregar la KEK sin que viaje entera?**
Shamir Secret Sharing, key wrapping asimétrico (cifrar con la clave pública del HSM destino), o Diffie-Hellman para derivar un secreto compartido sin que viaje por ningún medio.

**3. Si un custodio es comprometido, ¿queda comprometida la KEK?**
Con un componente: no — es indistinguible de datos aleatorios sin el otro. Con ambos comprometidos: sí, la KEK se reconstruye trivialmente.

---

## Dependencias

| Librería | Uso |
|---|---|
| `cryptography` | AES-CMAC para KCV, 3DES-ECB para KCV legacy y bonus |
| `psec` | Wrap/unwrap de key blocks TR-31 (ANSI X9.143) |
| `dukpt` | Derivación IPEK y future key |
| `bitstring` | API interna de dukpt |
| `pytest` | Tests |
