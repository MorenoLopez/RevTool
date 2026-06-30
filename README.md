# revtool

> Binary reverse engineering toolkit in C — file analysis, ELF/PE parsing, entropy scanning, string extraction, and optional disassembly.

A single self-contained CLI binary with no mandatory external dependencies: MD5/SHA1/SHA256 hashing, Shannon entropy, ELF and PE header parsing, and string extraction are all implemented from scratch on top of the C standard library and POSIX (`mmap`, `fstat`).

---

## Author

**4n0ny_m0**

---

## Table of Contents

- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Commands](#commands)
- [Architecture](#architecture)
- [License](#license)

---

## Requirements

- A C11 compiler (`gcc` or `clang`)
- `libm` (math library, used for entropy calculation)
- `capstone` — optional, enables real disassembly in the `disasm` command (falls back to a colorized hex dump otherwise)
- `libasan` — optional, only needed for the `debug` build (AddressSanitizer)

---

## Build

```bash
make              # standard release build
make test         # build, then run a quick smoke test against /bin/ls
make capstone     # build with Capstone disassembly support
make debug        # build with -fsanitize=address, no optimizations
make clean        # remove object files
make fclean       # remove object files and the binary
make install      # install to /usr/local/bin
make uninstall    # remove from /usr/local/bin
```

To build with Capstone manually (custom include/lib paths):

```bash
make USE_CAPSTONE=1 CAPSTONE_CFLAGS="-I/path/to/include" CAPSTONE_LDFLAGS="-L/path/to/lib"
```

---

## Usage

```bash
revtool <command> [options] <file>
```

```bash
revtool info /bin/ls                  # metadata, magic, hashes, entropy
revtool info -f /bin/ls               # same, plus full ELF/PE header dump
revtool hex -n 256 /bin/ls            # hex dump, 256 bytes
revtool hex -o 0x1000 -n 64 file.bin  # hex dump at a given offset
revtool strings -n 8 /bin/ls          # printable strings, min length 8
revtool elf /bin/ls                   # ELF header, program & section headers
revtool pe malware.exe                # PE/COFF header, section table
revtool entropy -t 7.0 /bin/ls        # entropy scan with custom threshold
revtool disasm -a x64 file.bin        # disassemble (requires Capstone build)
revtool disasm -a x86 -o 0x400 -s 512 -b 0x400 file.bin
revtool scan /bin/ls                  # run every module in sequence
```

Global flags: `--no-color` (disable ANSI output), `-h`/`--help`, `-v`/`--version`.

---

## Commands

| Command | Description |
|---|---|
| `info` | File size, type, MD5/SHA1/SHA256, Shannon entropy; `-f` adds a full ELF/PE breakdown |
| `hex` | Colorized hex dump with ASCII sidebar (`-o` offset, `-n` count, `-w` width) |
| `strings` | Extracts printable ASCII and UTF-16LE strings (`-n` minimum length) |
| `elf` | Parses ELF32/64 header, program headers, and section headers from raw bytes (no external ELF library) |
| `pe` | Parses DOS header, COFF header, optional header (PE32/PE32+), and section table |
| `entropy` | Shannon entropy over the whole file plus a sliding-window scan to flag packed/encrypted regions (`-w` window, `-t` threshold) |
| `disasm` | Disassembles a code region via Capstone (x86, x64, ARM, ARM64); hex fallback if Capstone is unavailable |
| `scan` | Runs `info -f`, `entropy`, `strings`, and `hex` back to back for a quick full overview |

---

## Architecture

```
RevTool/
├── revtool.c      # entry point, argument pre-processing, command dispatch
├── common.h        # shared structs, prototypes, ANSI color helpers
├── common.c         # file_t (mmap-backed file handling), entropy, MD5/SHA1/SHA256, magic detection
├── info.c            # `info` command
├── hexdump.c          # `hex` command
├── strings.c           # `strings` command
├── elf.c                # `elf` command — standalone ELF32/64 parser
├── pe.c                   # `pe` command — standalone PE/COFF parser
├── entropy.c                # `entropy` command
├── disasm.c                   # `disasm` command — Capstone wrapper with hex fallback
├── scan.c                       # `scan` command — orchestrates the others
└── Makefile
```

Files are memory-mapped read-only via `mmap` and always released through `file_close()`, which also closes the underlying file descriptor — no manual `open`/`close` pairs scattered across modules. ELF and PE structures are read directly from the mapped bytes using small endian-aware accessor functions, so the tool has zero parsing dependencies even for binary format internals.

---

## License

This project is licensed under the [MIT License](LICENSE).