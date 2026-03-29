"""
Tests para dukpt.py — derivación IPEK y future key con vectores del enunciado.
"""

import pytest
from key_exchange.dukpt import run_dukpt_bonus


BDK = bytes.fromhex("39ede3a9437f3ff561898d1f6fabbd25")
DEFAULT_KSN = "FFFF9876543210E00002"


class TestRunDukptBonus:
    def test_returns_expected_keys(self):
        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        assert "ksn" in result
        assert "ipek" in result
        assert "future_key" in result
        assert "plaintext" not in result

    def test_ksn_uppercased_in_result(self):
        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN.lower())
        assert result["ksn"] == DEFAULT_KSN.upper()

    def test_ipek_is_16_bytes(self):
        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        assert len(bytes.fromhex(result["ipek"])) == 16

    def test_future_key_is_16_bytes(self):
        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        assert len(bytes.fromhex(result["future_key"])) == 16

    def test_deterministic_with_same_inputs(self):
        r1 = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        r2 = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        assert r1["ipek"] == r2["ipek"]
        assert r1["future_key"] == r2["future_key"]

    def test_decrypt_with_ciphertext(self):
        # Cifrar datos de prueba con la future key para luego descifrarlos
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.backends import default_backend
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

        result_no_ct = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        future_key = bytes.fromhex(result_no_ct["future_key"])
        # Expandir a 24 bytes (3DES-112 → 3DES-168)
        key24 = future_key + future_key[:8]
        plaintext = b"TestData"  # 8 bytes = 1 bloque 3DES
        cipher = Cipher(TripleDES(key24), modes.ECB(), backend=default_backend())
        ciphertext = cipher.encryptor().update(plaintext)

        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN, ciphertext_hex=ciphertext.hex())
        assert bytes.fromhex(result["plaintext"]) == plaintext
