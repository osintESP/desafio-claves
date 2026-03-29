"""
kek.py — Ensamblado de la KEK por XOR de dos componentes y validación KCV.
"""

import os
import re
from .kcv import cmac_kcv, verify_kcv

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def _load_component(value: str) -> bytes:
    """
    Acepta un valor hex directo o una ruta a un archivo que contenga el hex.
    """
    if not isinstance(value, str):
        raise TypeError("El componente debe ser un string hex o una ruta a archivo")
    if not value:
        raise ValueError("El componente no puede estar vacío")
    if os.path.isfile(value):
        with open(value, "r") as f:
            value = f.read().strip()
        if not value:
            raise ValueError("El archivo del componente está vacío")
    if not _HEX_RE.match(value):
        raise ValueError("El componente contiene caracteres no hexadecimales")
    if len(value) % 2 != 0:
        raise ValueError("El componente debe tener un número par de caracteres hex")
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
