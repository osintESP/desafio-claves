"""
dukpt.py — Bonus: derivación DUKPT (IPEK + future key) y descifrado 3DES-ECB.

API real de dukpt 1.x:
    dukpt.Server(bdk=bytes)
    server.generate_ipek(BitArray(bytes=ksn)) -> BitArray
    server.gen_key(BitArray(bytes=ksn))       -> bytes  (transaction/future key)
"""

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.backends import default_backend
import dukpt as dukpt_lib
from bitstring import BitArray


# KSN del enunciado
DEFAULT_KSN = "FFFF9876543210E00002"

_BDK_SIZE = 16   # 3DES-112
_KSN_SIZE = 10   # 10 bytes = 20 hex chars


def run_dukpt_bonus(bdk: bytes, ksn_hex: str = DEFAULT_KSN, ciphertext_hex: str = None) -> dict:
    """
    Ejecuta el flujo completo del bonus DUKPT:
        BDK + KSN → IPEK → future key → (opcional) descifrado 3DES-ECB

    Args:
        bdk: Base Derivation Key como bytes (16 bytes, 3DES-112)
        ksn_hex: Key Serial Number en hex (10 bytes = 20 chars)
        ciphertext_hex: datos cifrados en hex para descifrar con la future key

    Returns:
        dict con ksn, ipek, future_key y (si hay ciphertext) plaintext
    """
    if not isinstance(bdk, bytes):
        raise TypeError("bdk debe ser bytes")
    if len(bdk) != _BDK_SIZE:
        raise ValueError(f"BDK debe tener {_BDK_SIZE} bytes (recibido: {len(bdk)})")

    if not isinstance(ksn_hex, str) or not ksn_hex:
        raise ValueError("ksn_hex debe ser un string hex no vacío")
    if len(ksn_hex) != _KSN_SIZE * 2:
        raise ValueError(f"KSN debe tener {_KSN_SIZE * 2} caracteres hex (recibido: {len(ksn_hex)})")

    if ciphertext_hex is not None:
        ct_bytes = bytes.fromhex(ciphertext_hex)
        if len(ct_bytes) == 0:
            raise ValueError("El ciphertext no puede estar vacío")
        if len(ct_bytes) % 8 != 0:
            raise ValueError(
                f"El ciphertext debe ser múltiplo de 8 bytes para 3DES-ECB (recibido: {len(ct_bytes)} bytes)"
            )

    try:
        ksn_bytes = bytes.fromhex(ksn_hex)
        ksn_bits = BitArray(bytes=ksn_bytes)

        server = dukpt_lib.Server(bdk=bdk)
        ipek_bits = server.generate_ipek(ksn_bits)
        ipek = ipek_bits.bytes

        # gen_key() está roto cuando recibe un BitArray (lo convierte a 640 bits).
        # Llamamos generate_ipek + derive_key directamente usando ksn como bytes.
        future_key_bits = server.derive_key(ipek_bits, BitArray(bytes=ksn_bytes))
        future_key = future_key_bits.bytes
    except Exception as e:
        raise ValueError(f"Error en derivación DUKPT: {e}") from e

    result = {
        "ksn": ksn_hex.upper(),
        "ipek": ipek.hex().upper(),
        "future_key": future_key.hex().upper(),
    }

    if ciphertext_hex:
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = _decrypt_3des_ecb(future_key, ciphertext)
        result["plaintext"] = plaintext.hex().upper()

    return result


def _decrypt_3des_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Descifra datos con 3DES-ECB."""
    if len(key) not in (16, 24):
        raise ValueError(f"La future key debe tener 16 o 24 bytes (recibido: {len(key)})")
    # Expandir clave de 16 a 24 bytes si es necesario (3DES-112 → 3DES-168)
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(
        TripleDES(key),
        modes.ECB(),
        backend=default_backend(),
    )
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()
