# x64 recompilation prototype

Isolated from the 2011 Legendary Edition pipeline (`tools/lift.py`, `tools/discover.py`, `runtime/`, `android/`). This directory does not load a game, does not build an APK, and does not decode a PE32+ optional header with PE32 offsets.

A match here means clang `-O2` produced the same registers, defined flags, and memory as Unicorn x86-64 for a synthetic fixture. It does not mean Skyrim Anniversary Edition runs.

## What is supported

| Instruction | Forms |
| --- | --- |
| `nop` | no operands |
| `mov` / `movabs` | reg, imm; reg, reg; reg, mem; mem, reg |
| `movzx` | reg, reg |
| `add` | reg, reg; reg, imm |
| `sub`, `and`, `or`, `xor`, `cmp`, `test` | reg, reg |

Widths are 8, 16, 32, and 64. A 32-bit write zero-extends. An 8- or 16-bit write keeps the upper bits. `R8`–`R15` use the same paths as `RAX`–`RDI`. RIP-relative `mov` uses `insn_end + disp32`. Other memory forms are base register plus a displacement, with no index and no segment.

Defined flags compared with Unicorn: CF, PF, ZF, SF, OF, and AF for `add`, `sub`, and `cmp`. `and`, `or`, `xor`, and `test` leave AF unchanged because the architecture leaves it undefined, and the differential test skips AF for those snippets.

Guest memory is a 64 KiB identity map at address 0 (`MEMSZ`). Snippets are at most 4096 bytes and must lie inside that window.

## What is rejected

The lifter raises `Unsupported` and emits no runnable function for:

- a byte string that starts with `MZ` or `PE\0\0` (a PE image is not a fixture)
- `LOCK` (no atomic emulation in this milestone)
- `REP` / `REPE` / `REPNE`
- segment overrides and the address-size override (`0x67`)
- high-byte registers `AH`/`CH`/`DH`/`BH`
- indexed memory, absolute memory, and ALU or `movzx` memory forms not listed above
- `syscall`, control transfer, and every other mnemonic

`tools/x64/inspect_pe32plus.py` is the only tool that opens a PE. It accepts `IMAGE_FILE_MACHINE_AMD64` and magic `0x20B` only. `ImageBase` is the 8-byte field at optional-header offset 24. Import thunks are 8 bytes, read from the data directory at optional-header offset 112. The entry-point RVA is printed and not disassembled. A `.bind` section is reported as a section; its presence or absence is not evidence that bytes are encrypted or decrypted.

## Run the tests

From the repository root, with capstone 5.0.7, unicorn 2.0.1.post1, and clang:

```sh
python3 -B tools/x64/test_proto.py
```

or `tools/x64/run_tests.sh`. The script also `py_compile`s the Legendary Edition tools. `tools/difftest.py` is not executed: it needs `TESV.exe`, which is not in this tree.

One checked-in fixture:

```sh
python3 tools/x64/difftest64.py --fixture tools/x64/fixtures/mov_eax_imm.json
```

## Inspect a PE32+ file the user already has

The Anniversary Edition executable is not in this repository. On the machine that has it:

```sh
python3 tools/x64/inspect_pe32plus.py /path/to/SkyrimSE.exe --json \
  --expect-sha256 21A6F8244A57E880D02E600ADF61178AB5483DB7B3CCA8DBFC97D7CA1F081E18
```

Owner-supplied structural identity for that file, not re-parsed here: 37157376 bytes, FileVersion 1.6.1170.0, machine AMD64, magic PE32+, ImageBase `0x140000000`, exception directory and a `.pdata` section present, a `.bind` section present, import DLLs include `d3d11.dll`, `dxgi.dll`, and `d3dx9_42.dll`. Filesystem timestamps from the desktop report are intentionally omitted. Exit code 2 is a rejected format, 3 is a SHA-256 mismatch. The file cap is 64 MiB. Do not pass this executable to `tools/lift.py` or `tools/x64/lift64.py`.

## Later leaf-function test

Still not a game run, and not implemented as an automatic scan:

1. Run the inspector. Do not start disassembly at `addressOfEntryPoint`. Do not read `.bind` as code, and do not treat that section as proof the image is packed or unpacked.
2. Choose one leaf inside an executable section whose every instruction is in the allowlist above, at most 4096 bytes, with no calls.
3. Slide that range into the 64 KiB window so `base + length <= 65536`, together with any RIP-relative data it reads or writes. Do not rewrite absolute immediates. If the leaf uses an address outside the window, stop; it is outside this prototype.
4. Save `{"base": <int>, "code_hex": "<hex>", "regs": {}, "mem": {"<addr>": "<hex>"}}` and run `python3 tools/x64/difftest64.py --fixture that.json`.
5. A match checks that leaf against Unicorn only.
