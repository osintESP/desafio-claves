"""
dukpt.py — Bonus: derivación DUKPT (IPEK + future key) y descifrado 3DES-ECB.

API real de dukpt 1.x:
    dukpt.Server(bdk=bytes)
    server.generate_ipek(BitArray(bytes=ksn)) -> BitArray
    server.gen_key(BitArray(bytes=ksn))       -> bytes  (transaction/future key)
"""

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
import dukpt as dukpt_lib
from bitstring import BitArray


# KSN del enunciado
DEFAULT_KSN = "FFFF9876543210E00002"


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
    ksn_bytes = bytes.fromhex(ksn_hex)
    ksn_bits = BitArray(bytes=ksn_bytes)

    server = dukpt_lib.Server(bdk=bdk)
    ipek_bits = server.generate_ipek(ksn_bits)
    ipek = ipek_bits.bytes

    # gen_key() está roto cuando recibe un BitArray (lo convierte a 640 bits).
    # Llamamos generate_ipek + derive_key directamente usando ksn como bytes.
    future_key_bits = server.derive_key(ipek_bits, BitArray(bytes=ksn_bytes))
    future_key = future_key_bits.bytes

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
