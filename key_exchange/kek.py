"""
kek.py — Ensamblado de la KEK por XOR de dos componentes y validación KCV.
"""

import os
from .kcv import cmac_kcv, verify_kcv


def _load_component(value: str) -> bytes:
    """
    Acepta un valor hex directo o una ruta a un archivo que contenga el hex.
    """
    if os.path.isfile(value):
        with open(value, "r") as f:
            value = f.read().strip()
    return bytes.fromhex(value)


def assemble_kek(component1: str, component2: str, expected_kcv: str) -> bytes:
    """
    XOR de los dos componentes para obtener la KEK AES-256.
    Verifica el KCV con CMAC-KCV antes de retornar.

    Args:
        component1: hex string o ruta al archivo con el componente 1
        component2: hex string o ruta al archivo con el componente 2
        expected_kcv: KCV esperado en hex (3 bytes = 6 caracteres)

    Returns:
        KEK como bytes (32 bytes para AES-256)

    Raises:
        ValueError: si los componentes tienen longitudes distintas o el KCV no coincide
    """
    c1 = _load_component(component1)
    c2 = _load_component(component2)

    if len(c1) != len(c2):
        raise ValueError(
            f"Los componentes deben tener la misma longitud: "
            f"c1={len(c1)} bytes, c2={len(c2)} bytes"
        )

    kek = bytes(a ^ b for a, b in zip(c1, c2))
    kcv = cmac_kcv(kek)
    verify_kcv(kcv, expected_kcv, "KEK")
    return kek
