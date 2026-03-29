"""
__main__.py — CLI: subcomandos export-pek e import-bdk.

Uso:
    python -m key_exchange export-pek --kek-component-1 ... --kek-component-2 ... --kek-kcv ... --out ...
    python -m key_exchange import-bdk --kek-component-1 ... --kek-component-2 ... --kek-kcv ... --bdk-keyblock ... --bdk-kcv ...
"""

import argparse
import os
import sys

from .kek import assemble_kek
from .kcv import legacy_kcv, cmac_kcv, verify_kcv
from .keyblock import unwrap_keyblock, wrap_keyblock
from .dukpt import run_dukpt_bonus


def _validate_hex(value: str, name: str, expected_bytes: int = None) -> None:
    """Valida que value sea un hex string válido y, opcionalmente, de la longitud esperada."""
    # Si es una ruta a archivo, la validación ocurre al leer el contenido
    if os.path.isfile(value):
        return
    if len(value) % 2 != 0:
        raise ValueError(f"{name} debe tener un número par de caracteres hex (recibido: {len(value)} chars)")
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} contiene caracteres no hex: '{value}'")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise ValueError(
            f"{name} debe tener {expected_bytes} bytes ({expected_bytes * 2} chars hex), "
            f"recibido: {len(decoded)} bytes"
        )


def _validate_inputs_kek(args) -> None:
    _validate_hex(args.kek_component_1, "kek-component-1")
    _validate_hex(args.kek_component_2, "kek-component-2")
    _validate_hex(args.kek_kcv, "kek-kcv", expected_bytes=3)


def cmd_export_pek(args):
    _validate_inputs_kek(args)

    print("[*] Ensamblando KEK...")
    kek = assemble_kek(args.kek_component_1, args.kek_component_2, args.kek_kcv)
    print(f"[+] KEK válida. KCV={args.kek_kcv.upper()}")

    print("[*] Generando PEK aleatoria (AES-256)...")
    pek = os.urandom(32)
    kcv = cmac_kcv(pek)
    print(f"[+] PEK generada. KCV={kcv.hex().upper()}")

    print("[*] Envolviendo PEK en key block TR-31...")
    keyblock = wrap_keyblock(pek, kek, key_usage="P0")

    if args.out:
        with open(args.out, "w") as f:
            f.write(keyblock + "\n")
        print(f"[+] Key block guardado en: {args.out}")
    else:
        print(f"[+] Key block TR-31:\n{keyblock}")

    print(f"[+] KCV de la PEK: {kcv.hex().upper()}")


def cmd_import_bdk(args):
    _validate_inputs_kek(args)
    _validate_hex(args.bdk_kcv, "bdk-kcv", expected_bytes=3)
    if args.ksn is not None:
        _validate_hex(args.ksn, "ksn", expected_bytes=10)
    if args.ciphertext is not None:
        ct_bytes = len(bytes.fromhex(args.ciphertext))
        if ct_bytes % 8 != 0:
            raise ValueError(
                f"ciphertext debe ser múltiplo de 8 bytes para 3DES-ECB (recibido: {ct_bytes} bytes)"
            )

    print("[*] Ensamblando KEK...")
    kek = assemble_kek(args.kek_component_1, args.kek_component_2, args.kek_kcv)
    print(f"[+] KEK válida. KCV={args.kek_kcv.upper()}")

    print("[*] Desenvolviendo key block TR-31 de la BDK...")
    bdk = unwrap_keyblock(args.bdk_keyblock, kek)
    print(f"[+] BDK desenvuelta: {len(bdk)*8} bits")

    print("[*] Verificando KCV de la BDK...")
    bdk_kcv = legacy_kcv(bdk)
    verify_kcv(bdk_kcv, args.bdk_kcv, "BDK")
    print(f"[+] BDK válida. KCV={args.bdk_kcv.upper()}")

    # Bonus DUKPT
    print("\n[*] Ejecutando bonus DUKPT...")
    ksn = args.ksn or "FFFF9876543210E00002"
    result = run_dukpt_bonus(bdk, ksn_hex=ksn, ciphertext_hex=args.ciphertext)
    print(f"[+] KSN       : {result['ksn']}")
    print(f"[+] IPEK      : {result['ipek']}")
    print(f"[+] Future Key: {result['future_key']}")
    if "plaintext" in result:
        print(f"[+] Plaintext : {result['plaintext']}")


def main():
    parser = argparse.ArgumentParser(
        prog="key_exchange",
        description="Desafío Técnico MercadoPago — Intercambio de claves criptográficas",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- export-pek ---
    p_export = sub.add_parser("export-pek", help="Genera y exporta una PEK en key block TR-31")
    p_export.add_argument("--kek-component-1", required=True, metavar="HEX_O_RUTA")
    p_export.add_argument("--kek-component-2", required=True, metavar="HEX_O_RUTA")
    p_export.add_argument("--kek-kcv", required=True, metavar="HEX")
    p_export.add_argument("--out", metavar="RUTA", help="Archivo de salida para el key block")

    # --- import-bdk ---
    p_import = sub.add_parser("import-bdk", help="Importa y valida la BDK desde un key block TR-31")
    p_import.add_argument("--kek-component-1", required=True, metavar="HEX_O_RUTA")
    p_import.add_argument("--kek-component-2", required=True, metavar="HEX_O_RUTA")
    p_import.add_argument("--kek-kcv", required=True, metavar="HEX")
    p_import.add_argument("--bdk-keyblock", required=True, metavar="KEYBLOCK_O_RUTA")
    p_import.add_argument("--bdk-kcv", required=True, metavar="HEX")
    p_import.add_argument("--ksn", metavar="HEX", help="KSN para el bonus DUKPT (10 bytes)")
    p_import.add_argument("--ciphertext", metavar="HEX", help="Datos cifrados para descifrar con la future key")

    args = parser.parse_args()

    try:
        if args.command == "export-pek":
            cmd_export_pek(args)
        elif args.command == "import-bdk":
            cmd_import_bdk(args)
    except ValueError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
