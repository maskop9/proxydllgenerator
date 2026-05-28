"""Detect MinGW-w64 cross-compilers and invoke them to build proxy DLLs."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Architecture configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArchConfig:
    label: str                        # human-readable  e.g. "AMD/x64"
    compiler: str                     # primary compiler binary name
    alt_compilers: tuple[str, ...]    # fallback names to try
    output_subdir: str                # relative path inside the output root
    machine_types: tuple[int, ...]    # PE Machine values this arch corresponds to
    extra_link_flags: tuple[str, ...] = ()  # arch-specific linker flags


AMD_X64 = ArchConfig(
    label="AMD/x64",
    compiler="x86_64-w64-mingw32-gcc",
    alt_compilers=("x86_64-w64-mingw32-gcc-win32", "x86_64-w64-mingw32-gcc-posix"),
    output_subdir=os.path.join("AMD", "x64"),
    machine_types=(0x8664,),
)

AMD_X86 = ArchConfig(
    label="AMD/x86",
    compiler="i686-w64-mingw32-gcc",
    alt_compilers=("i686-w64-mingw32-gcc-win32", "i686-w64-mingw32-gcc-posix"),
    output_subdir=os.path.join("AMD", "x86"),
    machine_types=(0x014C,),
    # --kill-at strips the @N stdcall decoration from exported symbol names
    # so the DLL exports 'FuncA' rather than '_FuncA@8'
    extra_link_flags=("-Wl,--kill-at",),
)

ALL_ARCH_CONFIGS: dict[str, ArchConfig] = {
    "x64": AMD_X64,
    "x86": AMD_X86,
}


# ---------------------------------------------------------------------------
# Compiler discovery
# ---------------------------------------------------------------------------

def find_compiler(cfg: ArchConfig) -> Optional[str]:
    """Return the path to the first available compiler for this arch, or None."""
    for name in (cfg.compiler,) + cfg.alt_compilers:
        path = shutil.which(name)
        if path:
            return path

    # On Windows, also check common MinGW/MSYS2 install locations
    if platform.system() == "Windows":
        search_roots = [
            r"C:\msys64\mingw64\bin",
            r"C:\msys64\mingw32\bin",
            r"C:\mingw64\bin",
            r"C:\mingw32\bin",
            r"C:\Program Files\mingw-w64",
        ]
        for root in search_roots:
            for name in (cfg.compiler,) + cfg.alt_compilers:
                candidate = os.path.join(root, name + ".exe")
                if os.path.isfile(candidate):
                    return candidate

    return None


def check_compilers(architectures: list[str]) -> dict[str, Optional[str]]:
    """
    Return a dict mapping arch name -> compiler path (or None if not found).
    """
    return {arch: find_compiler(ALL_ARCH_CONFIGS[arch]) for arch in architectures}


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

_COMMON_FLAGS = [
    "-O2",  # optimise
    "-s",   # strip symbols – smaller output
]


def compile_dll(
    arch: str,
    c_path: str,
    asm_path: str,
    def_path: str,
    output_dll: str,
    compiler_path: str,
    verbose: bool = False,
    extra_link_flags: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """
    Invoke the MinGW cross-compiler to build the proxy DLL.

    Args:
        extra_link_flags: Additional linker flags appended after the
                          architecture defaults (e.g. ``("-lbcrypt",)``
                          when AES encryption is used).

    Returns:
        (success, message)
    """
    cfg = ALL_ARCH_CONFIGS[arch]
    cmd = [
        compiler_path,
        "-shared",
        "-o", output_dll,
        c_path,
        asm_path,   # assembly stubs (separate .s file avoids inline-asm name issues)
        def_path,
    ] + _COMMON_FLAGS + list(cfg.extra_link_flags) + list(extra_link_flags)

    if verbose:
        print(f"    CMD: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out after 120 s"
    except FileNotFoundError:
        return False, f"Compiler executable not found: {compiler_path}"
    except OSError as exc:
        return False, f"Failed to launch compiler: {exc}"

    if result.returncode == 0:
        size = os.path.getsize(output_dll)
        msg = f"OK – {output_dll} ({size:,} bytes)"
        if result.stderr.strip() and verbose:
            msg += f"\n    Warnings:\n{result.stderr.strip()}"
        return True, msg

    stderr = result.stderr.strip() or "(no output)"
    return False, f"Compiler exited {result.returncode}:\n{stderr}"


# ---------------------------------------------------------------------------
# Installation hint helpers
# ---------------------------------------------------------------------------

def install_hint(arch: str) -> str:
    cfg = ALL_ARCH_CONFIGS[arch]
    system = platform.system()
    if system == "Linux":
        return (
            f"  Ubuntu/Debian : sudo apt-get install mingw-w64\n"
            f"  Fedora/RHEL   : sudo dnf install mingw64-gcc mingw32-gcc\n"
            f"  Arch Linux    : sudo pacman -S mingw-w64-gcc"
        )
    elif system == "Darwin":
        return "  macOS : brew install mingw-w64"
    elif system == "Windows":
        return (
            "  Windows: install MSYS2 (https://www.msys2.org/) then run:\n"
            "    pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc"
        )
    else:
        return f"  Install {cfg.compiler} for your platform"
