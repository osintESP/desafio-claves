"""
Tests para la validación de entradas del CLI (__main__.py).
"""

import pytest
from unittest.mock import patch, MagicMock
from key_exchange.__main__ import _validate_hex


class TestValidateHex:
    def test_valid_hex_passes(self):
        _validate_hex("F74B90", "test")  # sin excepción

    def test_odd_length_raises(self):
        with pytest.raises(ValueError, match="par de caracteres"):
            _validate_hex("F74B9", "test")

    def test_invalid_chars_raises(self):
        with pytest.raises(ValueError, match="no hex"):
            _validate_hex("ZZZZZZ", "test")

    def test_wrong_byte_length_raises(self):
        with pytest.raises(ValueError, match="3 bytes"):
            _validate_hex("F74B9000", "test", expected_bytes=3)

    def test_correct_byte_length_passes(self):
        _validate_hex("F74B90", "test", expected_bytes=3)  # sin excepción

    def test_file_path_skips_validation(self, tmp_path):
        # Si es una ruta a archivo, la validación se difiere a la lectura
        p = tmp_path / "comp.hex"
        p.write_text("not_validated_here")
        _validate_hex(str(p), "test")  # sin excepción aunque el contenido sea inválido
