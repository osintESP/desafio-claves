"""
kcv.py — Cálculo de Key Check Value (KCV)

- CMAC-KCV (AES): para claves AES (e.g. KEK AES-256)
- KCV legacy (3DES-ECB): para claves 3DES (e.g. BDK)
"""

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def cmac_kcv(key: bytes, length: int = 3) -> bytes:
    """
    Calcula el CMAC-KCV de una clave AES.
    Devuelve los primeros `length` bytes del CMAC sobre 16 bytes en cero.
    """
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(b"\x00" * 16)
    mac = c.finalize()
    return mac[:length]


def legacy_kcv(key: bytes, length: int = 3) -> bytes:
    """
    Calcula el KCV legacy (3DES-ECB) de una clave 3DES.
    Cifra 8 bytes en cero con 3DES-ECB y devuelve los primeros `length` bytes.
    """
    cipher = Cipher(
        algorithms.TripleDES(key),
        modes.ECB(),
        backend=default_backend(),
    )
    enc = cipher.encryptor()
    result = enc.update(b"\x00" * 8) + enc.finalize()
    return result[:length]


def verify_kcv(computed: bytes, expected_hex: str, label: str) -> None:
    """
    Compara el KCV calculado contra el esperado (hex string).
    Lanza ValueError con mensaje claro si no coinciden.
    """
    expected = bytes.fromhex(expected_hex)
    if computed != expected:
        raise ValueError(
            f"KCV inválido para {label}: "
            f"calculado={computed.hex().upper()}, "
            f"esperado={expected_hex.upper()}"
        )
