"""
Tests para kcv.py — vectores derivados de los datos del enunciado.
"""

import pytest
from key_exchange.kcv import cmac_kcv, legacy_kcv, verify_kcv


# KEK = XOR(component1, component2) del enunciado
KEK = bytes.fromhex(
    "c5a5117469a79c794720b20989257444ad33ff4f7659851a0dd727f555e74d61"
)

# BDK desenvuelta del enunciado (16 bytes, 3DES-112)
BDK = bytes.fromhex("39ede3a9437f3ff561898d1f6fabbd25")


class TestCmacKcv:
    def test_returns_3_bytes_by_default(self):
        kcv = cmac_kcv(KEK)
        assert len(kcv) == 3

    def test_kek_kcv_matches_enunciado(self):
        kcv = cmac_kcv(KEK)
        assert kcv.hex().upper() == "F74B90"

    def test_custom_length(self):
        kcv = cmac_kcv(KEK, length=5)
        assert len(kcv) == 5
        assert kcv[:3].hex().upper() == "F74B90"

    def test_deterministic(self):
        assert cmac_kcv(KEK) == cmac_kcv(KEK)


class TestLegacyKcv:
    def test_returns_3_bytes_by_default(self):
        kcv = legacy_kcv(BDK)
        assert len(kcv) == 3

    def test_bdk_kcv_matches_enunciado(self):
        kcv = legacy_kcv(BDK)
        assert kcv.hex().upper() == "EABBDC"

    def test_deterministic(self):
        assert legacy_kcv(BDK) == legacy_kcv(BDK)


class TestVerifyKcv:
    def test_valid_kcv_does_not_raise(self):
        kcv = cmac_kcv(KEK)
        verify_kcv(kcv, "F74B90", "KEK")  # sin excepción

    def test_invalid_kcv_raises_value_error(self):
        with pytest.raises(ValueError, match="KEK"):
            verify_kcv(b"\x00\x00\x00", "F74B90", "KEK")

    def test_error_message_contains_computed_and_expected(self):
        with pytest.raises(ValueError, match="000000"):
            verify_kcv(b"\x00\x00\x00", "F74B90", "KEK")
