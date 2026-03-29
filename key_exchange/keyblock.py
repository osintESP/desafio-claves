"""
keyblock.py — Wrap y unwrap de key blocks TR-31 usando la librería psec.

API real de psec 1.x:
    psec.tr31.unwrap(kbpk, key_block) -> (Header, bytes)
    psec.tr31.wrap(kbpk, header, key) -> str
"""

import os
import psec.tr31

# Usos de clave válidos según ANSI X9.143 / TR-31
_VALID_KEY_USAGES = {
    "B0", "B1", "B2",           # BDK
    "C0",                        # CVK
    "D0", "D1", "D2",           # Data encryption
    "E0", "E1", "E2", "E3",     # EMV/chip
    "I0",                        # IV
    "K0", "K1", "K2",           # Key encryption/wrapping
    "M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8",  # MAC
    "P0",                        # PIN encryption
    "S0", "S1", "S2",           # Asymmetric signature
    "V0", "V1", "V2", "V3", "V4",  # PIN verification
}

# Tamaños de clave criptográficamente válidos (bytes)
_VALID_KEY_SIZES = (8, 16, 24, 32)


def unwrap_keyblock(keyblock: str, kek: bytes) -> bytes:
    """
    Desenvuelve un key block TR-31 usando la KEK.
    psec verifica el MAC antes de descifrar (fail fast).

    Args:
        keyblock: key block TR-31 como string (o ruta a archivo)
        kek: KEK (KBPK) como bytes

    Returns:
        clave desenvuelta como bytes
    """
    if not isinstance(keyblock, str):
        raise TypeError("keyblock debe ser un string")
    if not isinstance(kek, bytes):
        raise TypeError("kek debe ser bytes")
    if not keyblock:
        raise ValueError("El key block no puede estar vacío")

    if os.path.isfile(keyblock):
        with open(keyblock, "r") as f:
            keyblock = f.read().strip()
        if not keyblock:
            raise ValueError("El archivo del key block está vacío")

    _header, key = psec.tr31.unwrap(kbpk=kek, key_block=keyblock)
    return key


def wrap_keyblock(key: bytes, kek: bytes, key_usage: str = "P0") -> str:
    """
    Envuelve una clave en un key block TR-31 versión D (AES KBPK).

    Args:
        key: clave a envolver como bytes
        kek: KEK (KBPK) AES como bytes
        key_usage: uso de la clave según TR-31 (default 'P0' = PIN Encryption Key)

    Returns:
        key block TR-31 como string
    """
    if not isinstance(key, bytes):
        raise TypeError("key debe ser bytes")
    if not isinstance(kek, bytes):
        raise TypeError("kek debe ser bytes")
    if len(key) not in _VALID_KEY_SIZES:
        raise ValueError(
            f"Tamaño de clave inválido: {len(key)} bytes. "
            f"Debe ser uno de: {sorted(_VALID_KEY_SIZES)}"
        )
    if key_usage not in _VALID_KEY_USAGES:
        raise ValueError(
            f"key_usage '{key_usage}' no es un valor TR-31 válido"
        )

    # Algoritmo según la longitud de la clave
    if len(key) == 16:
        algorithm = "T"  # Triple-DES 112-bit
    elif len(key) == 24:
        algorithm = "R"  # Triple-DES 168-bit
    else:
        algorithm = "A"  # AES (128/192/256) o DES (8 bytes)

    # Header TR-31 versión D (AES KBPK): longitud 0000 se calcula automáticamente
    header = f"D0000{key_usage}{algorithm}E00S0000"

    return psec.tr31.wrap(kbpk=kek, header=header, key=key)
