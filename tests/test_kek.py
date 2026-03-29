"""
Tests para kek.py — vectores del enunciado.
"""

import os
import tempfile
import pytest
from key_exchange.kek import assemble_kek, _load_component


COMPONENT_1 = "db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6"
COMPONENT_2 = "1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7"
KEK_KCV = "F74B90"
EXPECTED_KEK = bytes.fromhex(
    "c5a5117469a79c794720b20989257444ad33ff4f7659851a0dd727f555e74d61"
)


class TestLoadComponent:
    def test_loads_hex_string(self):
        result = _load_component(COMPONENT_1)
        assert result == bytes.fromhex(COMPONENT_1)

    def test_loads_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(COMPONENT_1 + "\n")
            path = f.name
        try:
            result = _load_component(path)
            assert result == bytes.fromhex(COMPONENT_1)
        finally:
            os.unlink(path)


class TestAssembleKek:
    def test_xor_produces_correct_kek(self):
        kek = assemble_kek(COMPONENT_1, COMPONENT_2, KEK_KCV)
        assert kek == EXPECTED_KEK

    def test_kek_is_32_bytes(self):
        kek = assemble_kek(COMPONENT_1, COMPONENT_2, KEK_KCV)
        assert len(kek) == 32

    def test_wrong_kcv_raises(self):
        with pytest.raises(ValueError, match="KEK"):
            assemble_kek(COMPONENT_1, COMPONENT_2, "000000")

    def test_mismatched_lengths_raises(self):
        short = COMPONENT_1[:32]  # 16 bytes en lugar de 32
        with pytest.raises(ValueError, match="longitud"):
            assemble_kek(short, COMPONENT_2, KEK_KCV)
