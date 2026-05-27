# proxydllgenerator

A Python tool that automates building proxy DLLs for DLL hijacking.  
Given an original DLL and a raw shellcode payload, it generates a
replacement DLL that:

- **Forwards** every named export to the original DLL via PE linker-level
  forwarder entries (DEF file `Name=original.Name` syntax).
- **Executes** the shellcode payload in a dedicated thread spawned from
  `DllMain` on `DLL_PROCESS_ATTACH`, avoiding loader-lock issues.

Compilation is performed by **MinGW-w64 cross-compilers**, so the tool
works identically on Linux, macOS, and Windows regardless of the host
architecture.

---

## Prerequisites

### 1 – Python 3.9 or newer

```
python --version   # must be >= 3.9
```

### 2 – Python dependencies

```bash
pip install -r requirements.txt
```

| Package | Minimum version | Purpose |
|---------|-----------------|---------|
| `pefile` | 2023.2.7 | Parse PE export directories |

### 3 – MinGW-w64 cross-compilers

The tool requires the following compiler binaries to be in `PATH`:

| Target arch | Required binary |
|-------------|-----------------|
| AMD x64 | `x86_64-w64-mingw32-gcc` |
| AMD x86 | `i686-w64-mingw32-gcc` |

#### Linux (Ubuntu / Debian)

```bash
sudo apt-get update
sudo apt-get install mingw-w64
```

#### Linux (Fedora / RHEL / AlmaLinux)

```bash
sudo dnf install mingw64-gcc mingw32-gcc
```

#### Linux (Arch Linux)

```bash
sudo pacman -S mingw-w64-gcc
```

#### macOS

```bash
brew install mingw-w64
```

> **Note:** The Homebrew formula installs both x86_64 and i686 compilers.

#### Windows (MSYS2 — recommended)

1. Download and install MSYS2 from <https://www.msys2.org/>
2. Open an **MSYS2 MinGW** shell and run:

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc
```

3. Add the MinGW `bin` directories to your Windows `PATH`:
   - `C:\msys64\mingw64\bin`
   - `C:\msys64\mingw32\bin`

#### Windows (standalone MinGW-w64)

Download the installer from <https://www.mingw-w64.org/downloads/> and
add the `bin` folder to your `PATH`.

---

## Installation

```bash
git clone <repo-url>
cd proxydllgenerator
pip install -r requirements.txt
```

No other installation steps are required.

---

## Usage

```
python proxydll.py -dll <DLL_PATH> -shellcode <SHELLCODE_PATH> [options]
```

### Required arguments

| Argument | Description |
|----------|-------------|
| `-dll <path>` | Path to the **original** DLL you want to proxy |
| `-shellcode <path>` | Path to a **raw binary** shellcode file |

### Optional arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `-arch x64\|x86\|all` | `all` | Target architecture(s) to build |
| `-o / --output <name>` | Same as input DLL | Output DLL base name (no extension) |
| `--orig-name <name>` | `<dll>_orig` | Base name the original DLL will be renamed to |
| `--output-dir <dir>` | `./output` | Root directory for compiled DLLs |
| `--keep-sources` | off | Retain generated `dllmain.c` and `proxy.def` |
| `-v / --verbose` | off | Print compiler commands and extra diagnostics |

---

## Examples

### Build proxy for all architectures (default)

```bash
python proxydll.py \
    -dll /path/to/version.dll \
    -shellcode /path/to/payload.bin
```

### Build only x64 proxy with a custom output name

```bash
python proxydll.py \
    -dll version.dll \
    -shellcode payload.bin \
    -arch x64 \
    -o version
```

### Specify the renamed-original name and inspect generated sources

```bash
python proxydll.py \
    -dll target.dll \
    -shellcode shell.bin \
    --orig-name target_backup \
    --keep-sources \
    -v
```

---

## Output structure

```
output/
└── AMD/
    ├── x64/
    │   └── <proxy_name>.dll
    └── x86/
        └── <proxy_name>.dll
```

When `--keep-sources` is set, the intermediate build files are placed in:

```
output/
└── _sources/
    ├── x64/
    │   ├── dllmain.c
    │   └── proxy.def
    └── x86/
        ├── dllmain.c
        └── proxy.def
```

---

## How it works

### Export forwarding (DEF file)

For each named export in the original DLL, the tool generates a DEF file
entry of the form:

```
ExportName=orig_name.ExportName @ordinal
```

This instructs the Windows linker to create a **PE forwarder entry** in
the export directory.  When the application resolves the import, the OS
loader transparently redirects it to `orig_name.dll` without any runtime
stub code.

> **Important:** The original DLL must be present at runtime under the
> `--orig-name` filename and in a directory the loader can find it
> (typically the same directory as the proxy).

### Ordinal-only exports

Exports that have no name (exported by ordinal only) **cannot** be
forwarded by this method.  The tool prints a warning for each one and
skips it.  If the target application imports those functions by ordinal,
the call will fail.  In practice, most modern Windows DLLs export by name.

### Shellcode execution

The shellcode bytes are embedded as a static `const unsigned char[]` array
in the DLL's `.rdata` section.  On `DLL_PROCESS_ATTACH`, the proxy:

1. Allocates a `PAGE_EXECUTE_READWRITE` region with `VirtualAlloc`.
2. Copies the shellcode bytes into it.
3. Spawns a new thread (`CreateThread`) that jumps to the shellcode.

Using a thread avoids holding the loader lock during shellcode execution.

---

## Deployment checklist

1. **Identify** a DLL search-order hijacking opportunity (e.g. missing DLL
   loaded from a writable user-controlled directory).
2. **Generate** the proxy DLL:
   ```bash
   python proxydll.py -dll target.dll -shellcode payload.bin
   ```
3. **Rename** the original DLL in the target directory:
   ```
   target.dll  →  target_orig.dll
   ```
4. **Drop** the generated proxy DLL:
   ```
   output/AMD/x64/target.dll  →  <target directory>/target.dll
   ```
5. Both `target.dll` (proxy) and `target_orig.dll` (original) must be in
   the same directory, or the original must be findable via the normal DLL
   search order.

---

## Limitations

- **ARM not supported** – ARM32/ARM64 Windows DLLs require `llvm-mingw`
  rather than standard MinGW-w64.  Run the tool on a host with
  `llvm-mingw` and adapt the compiler entries in `src/compiler.py` to
  add ARM targets.
- **Ordinal-only exports are skipped** – see above.
- **MSVC-style name mangling** – if the original DLL uses C++ mangled
  names, they are forwarded verbatim; unmangled wrapper names are not
  generated.
- **Shellcode must be position-independent** – the tool allocates memory
  at a random base address.  Ensure your shellcode does not rely on a
  fixed load address.

---

## Legal notice

This tool is intended for authorised security testing, penetration testing
engagements, red-team exercises, and educational purposes only.  Use on
systems you do not own or have explicit written permission to test is
illegal.  The authors accept no liability for misuse.
