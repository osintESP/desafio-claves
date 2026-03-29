"""
Tests para keyblock.py — wrap/unwrap TR-31 con vectores del enunciado.
"""

import os
import tempfile
import pytest
from key_exchange.keyblock import unwrap_keyblock, wrap_keyblock


KEK = bytes.fromhex(
    "c5a5117469a79c794720b20989257444ad33ff4f7659851a0dd727f555e74d61"
)
BDK_KEYBLOCK = (
    "D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76"
)
EXPECTED_BDK = bytes.fromhex("39ede3a9437f3ff561898d1f6fabbd25")


class TestUnwrapKeyblock:
    def test_unwraps_bdk_from_enunciado(self):
        bdk = unwrap_keyblock(BDK_KEYBLOCK, KEK)
        assert bdk == EXPECTED_BDK

    def test_unwraps_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(BDK_KEYBLOCK + "\n")
            path = f.name
        try:
            bdk = unwrap_keyblock(path, KEK)
            assert bdk == EXPECTED_BDK
        finally:
            os.unlink(path)

    def test_wrong_kek_raises(self):
        bad_kek = os.urandom(32)
        with pytest.raises(Exception):
            unwrap_keyblock(BDK_KEYBLOCK, bad_kek)

    def test_none_keyblock_raises_type_error(self):
        with pytest.raises(TypeError):
            unwrap_keyblock(None, KEK)

    def test_empty_keyblock_raises(self):
        with pytest.raises(ValueError, match="vacío"):
            unwrap_keyblock("", KEK)

    def test_empty_file_raises(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("")
        with pytest.raises(ValueError, match="vacío"):
            unwrap_keyblock(str(p), KEK)

    def test_none_kek_raises_type_error(self):
        with pytest.raises(TypeError):
            unwrap_keyblock(BDK_KEYBLOCK, None)


class TestWrapKeyblock:
    def test_wrap_produces_tr31_string(self):
        pek = os.urandom(32)
        keyblock = wrap_keyblock(pek, KEK, key_usage="P0")
        assert isinstance(keyblock, str)
        assert keyblock.startswith("D")  # versión D = AES KBPK

    def test_wrap_unwrap_roundtrip(self):
        pek = os.urandom(32)
        keyblock = wrap_keyblock(pek, KEK, key_usage="P0")
        recovered = unwrap_keyblock(keyblock, KEK)
        assert recovered == pek

    def test_invalid_key_usage_raises(self):
        pek = os.urandom(32)
        with pytest.raises(ValueError, match="TR-31"):
            wrap_keyblock(pek, KEK, key_usage="XX")

    def test_empty_key_usage_raises(self):
        pek = os.urandom(32)
        with pytest.raises(ValueError, match="TR-31"):
            wrap_keyblock(pek, KEK, key_usage="")

    def test_invalid_key_size_raises(self):
        for size in (0, 1, 7, 15, 17, 31, 33):
            with pytest.raises(ValueError, match="Tamaño de clave inválido"):
                wrap_keyblock(b"\x00" * size, KEK, key_usage="P0")

    def test_none_key_raises_type_error(self):
        with pytest.raises(TypeError):
            wrap_keyblock(None, KEK)

    def test_none_kek_raises_type_error(self):
        with pytest.raises(TypeError):
            wrap_keyblock(os.urandom(32), None)
