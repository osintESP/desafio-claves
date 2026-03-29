"""
kcv.py — Cálculo de Key Check Value (KCV)

- CMAC-KCV (AES): para claves AES (e.g. KEK AES-256)
- KCV legacy (3DES-ECB): para claves 3DES (e.g. BDK)
"""

import hmac

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.backends import default_backend

_AES_KEY_SIZES = (16, 24, 32)
_3DES_KEY_SIZES = (16, 24)


def cmac_kcv(key: bytes, length: int = 3) -> bytes:
    """
    Calcula el CMAC-KCV de una clave AES.
    Devuelve los primeros `length` bytes del CMAC sobre 16 bytes en cero.
    """
    if not isinstance(key, bytes):
        raise TypeError("key debe ser bytes")
    if len(key) not in _AES_KEY_SIZES:
        raise ValueError(f"key AES debe tener 16, 24 o 32 bytes (recibido: {len(key)})")
    try:
        c = CMAC(algorithms.AES(key), backend=default_backend())
        c.update(b"\x00" * 16)
        mac = c.finalize()
    except UnsupportedAlgorithm as e:
        raise ValueError(f"Algoritmo no soportado para CMAC-KCV: {e}") from e
    return mac[:length]


def legacy_kcv(key: bytes, length: int = 3) -> bytes:
    """
    Calcula el KCV legacy (3DES-ECB) de una clave 3DES.
    Cifra 8 bytes en cero con 3DES-ECB y devuelve los primeros `length` bytes.
    """
    if not isinstance(key, bytes):
        raise TypeError("key debe ser bytes")
    if len(key) not in _3DES_KEY_SIZES:
        raise ValueError(f"key 3DES debe tener 16 o 24 bytes (recibido: {len(key)})")
    cipher = Cipher(
        TripleDES(key),
        modes.ECB(),
        backend=default_backend(),
    )
    enc = cipher.encryptor()
    result = enc.update(b"\x00" * 8) + enc.finalize()
    return result[:length]


def verify_kcv(computed: bytes, expected_hex: str, label: str) -> None:
    """
    Compara el KCV calculado contra el esperado (hex string).
    Usa comparación en tiempo constante para evitar ataques de timing.
    Lanza ValueError con mensaje claro si no coinciden.
    """
    expected = bytes.fromhex(expected_hex)
    if not hmac.compare_digest(computed, expected):
        raise ValueError(f"KCV inválido para {label}")
