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
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.backends import default_backend

        result_no_ct = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN)
        future_key = bytes.fromhex(result_no_ct["future_key"])
        key24 = future_key + future_key[:8]
        plaintext = b"TestData"  # 8 bytes = 1 bloque 3DES
        cipher = Cipher(TripleDES(key24), modes.ECB(), backend=default_backend())
        ciphertext = cipher.encryptor().update(plaintext)

        result = run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN, ciphertext_hex=ciphertext.hex())
        assert bytes.fromhex(result["plaintext"]) == plaintext

    def test_bdk_wrong_type_raises(self):
        with pytest.raises(TypeError):
            run_dukpt_bonus("not bytes", ksn_hex=DEFAULT_KSN)

    def test_bdk_none_raises(self):
        with pytest.raises(TypeError):
            run_dukpt_bonus(None, ksn_hex=DEFAULT_KSN)

    def test_bdk_wrong_size_raises(self):
        for size in (0, 8, 12, 15, 17, 24, 32):
            with pytest.raises(ValueError, match="BDK debe tener"):
                run_dukpt_bonus(b"\x00" * size, ksn_hex=DEFAULT_KSN)

    def test_ksn_empty_raises(self):
        with pytest.raises(ValueError):
            run_dukpt_bonus(BDK, ksn_hex="")

    def test_ksn_none_raises(self):
        with pytest.raises(ValueError):
            run_dukpt_bonus(BDK, ksn_hex=None)

    def test_ksn_wrong_length_raises(self):
        for ksn in ("FF", "FFFF9876543210E0000", "FFFF9876543210E000F200"):
            with pytest.raises(ValueError, match="KSN debe tener"):
                run_dukpt_bonus(BDK, ksn_hex=ksn)

    def test_ciphertext_not_multiple_of_8_raises(self):
        for size in (1, 7, 9, 15):
            with pytest.raises(ValueError, match="múltiplo de 8"):
                run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN, ciphertext_hex="AA" * size)

    def test_ciphertext_empty_raises(self):
        with pytest.raises(ValueError, match="vacío"):
            run_dukpt_bonus(BDK, ksn_hex=DEFAULT_KSN, ciphertext_hex="")
