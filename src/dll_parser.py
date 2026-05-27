"""Parse exported symbols from a PE DLL using pefile."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import pefile


@dataclass
class ExportEntry:
    ordinal: int
    name: Optional[str] = None
    forwarder: Optional[str] = None
    address: int = 0


@dataclass
class DllInfo:
    path: str
    basename: str           # filename without extension
    machine: int            # IMAGE_FILE_MACHINE_* constant
    exports: list[ExportEntry] = field(default_factory=list)

    @property
    def arch_label(self) -> str:
        MACHINES = {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "ARM64",
            0x01C4: "ARM",
        }
        return MACHINES.get(self.machine, f"unknown(0x{self.machine:04X})")


def parse_dll(dll_path: str) -> DllInfo:
    """
    Parse a PE DLL file and return metadata + all export entries.

    Raises:
        FileNotFoundError: if dll_path does not exist.
        pefile.PEFormatError: if the file is not a valid PE.
        ValueError: if the file has no export directory.
    """
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"DLL not found: {dll_path}")

    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )

    basename = os.path.splitext(os.path.basename(dll_path))[0]
    machine = pe.FILE_HEADER.Machine

    exports: list[ExportEntry] = []

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name: Optional[str] = None
            if sym.name:
                try:
                    name = sym.name.decode("utf-8")
                except UnicodeDecodeError:
                    name = sym.name.decode("latin-1")

            forwarder: Optional[str] = None
            # pefile attribute name differs across versions: try both
            _fwd_raw = getattr(sym, "forwarder_string", None) or getattr(sym, "forwarder", None)
            if _fwd_raw:
                try:
                    forwarder = _fwd_raw.decode("utf-8")
                except UnicodeDecodeError:
                    forwarder = _fwd_raw.decode("latin-1")

            exports.append(
                ExportEntry(
                    ordinal=sym.ordinal,
                    name=name,
                    forwarder=forwarder,
                    address=sym.address or 0,
                )
            )

    pe.close()
    return DllInfo(path=dll_path, basename=basename, machine=machine, exports=exports)
