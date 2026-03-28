"""
keyblock.py — Wrap y unwrap de key blocks TR-31 usando la librería psec.

API real de psec 1.x:
    psec.tr31.unwrap(kbpk, key_block) -> (Header, bytes)
    psec.tr31.wrap(kbpk, header, key) -> str
"""

import os
import psec.tr31


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
    if os.path.isfile(keyblock):
        with open(keyblock, "r") as f:
            keyblock = f.read().strip()

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
    # Algoritmo según la longitud de la clave
    if len(key) == 16:
        algorithm = "T"  # Triple-DES 112-bit
    elif len(key) == 24:
        algorithm = "R"  # Triple-DES 168-bit
    else:
        algorithm = "A"  # AES (128/192/256)

    # Header TR-31 versión D (AES KBPK): longitud 0000 se calcula automáticamente
    header = f"D0000{key_usage}{algorithm}E00S0000"

    return psec.tr31.wrap(kbpk=kek, header=header, key=key)
