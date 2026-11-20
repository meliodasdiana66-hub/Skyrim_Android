# x64 recompilation prototype

Isolated from the 2011 Legendary Edition pipeline (`tools/lift.py`, `tools/discover.py`, `runtime/`, `android/`). This directory does not load a game, does not build an APK, and does not decode a PE32+ optional header with PE32 offsets.

A match here means clang `-O2` produced the same registers, defined flags, and memory as Unicorn x86-64 for a synthetic fixture. It does not mean Skyrim Anniversary Edition runs.

## What is supported

| Instruction | Forms |
| --- | --- |
| `nop` | no operands |
| `ret` | one final unprefixed `C3` only. It is not executed and must not read the stack. `C2` and a `ret` that is not last are rejected |
| `mov` / `movabs` | reg, imm; reg, reg; reg, mem; mem, reg |
| `movzx` | reg, reg |
| `add` | reg, reg; reg, imm |
| `sub`, `and`, `or`, `xor`, `cmp` | reg, reg |
| `test` | reg, reg; reg, imm. The immediate form sets CF, OF, SF, ZF, and PF and does not write the destination. AF stays unchanged |
| `push` / `pop` | r64 except RSP; `push imm8` and `push imm32` sign-extended to 64. A leaf may use them only inside a proven frame |

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
- `syscall`, calls, jumps, and every other mnemonic
- `push`/`pop` of RSP, 16-bit `push`/`pop`, and any stack access outside the frame this leaf allocated (`sub rsp, imm` allocates; `add rsp, imm` frees; a later read of a freed slot is rejected)
- indexed `lea`
- any `ret` except one final unprefixed `C3`, which is recognized and then not executed

`inspect_pe32plus.py` and `leafcheck.py` are the tools that open a PE. They accept `IMAGE_FILE_MACHINE_AMD64` and magic `0x20B` only. `ImageBase` is the 8-byte field at optional-header offset 24. Import thunks are 8 bytes, read from the data directory at optional-header offset 112. The entry-point RVA is printed and not disassembled. A `.bind` section is reported as a section; its presence or absence is not evidence that bytes are encrypted or decrypted.

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

## Leaf scan of a PE32+ file

`leafcheck.py` reads one executable on the machine where it already lives. Dry-run is standard-library Python: no capstone, unicorn, clang, or package install. It walks `.pdata` (`IMAGE_RUNTIME_FUNCTION`, 12 bytes) and keeps a range only when all of the following hold:

- the range is entirely inside one section with the executable characteristic, and the section name is not `.bind`
- the range does not contain `addressOfEntryPoint`
- the bytes decode as an allowlisted straight line of at most 4096 bytes, at least one instruction, and a final one-byte `ret`
- there is no call, jump, `LOCK`, or other rejected opcode
- every memory operand is either RIP-relative inside the 64 KiB window or `[rsp+disp]` / `push` / `pop` inside a frame this leaf itself allocated. RSP is then pinned. Calls, jumps, and other addresses stay rejected.

A row in `candidates` has `status: candidate_not_executed`. That is not a test result. `verifiedFunctions` is filled only by `--execute`, which needs capstone, unicorn, and clang already installed and runs four deterministic register/flag cases. Do not install those packages for this step unless that has been agreed. `--execute` still does not launch the game, does not unpack `.bind`, and does not write instruction or data bytes into the JSON.

The Anniversary Edition file was not on the machine that added this tool, so no candidate list for SHA-256 `21a6f8244a57e880d02e600adf61178ab5483db7b3cca8dbfc97d7ca1f081e18` exists here. Windows commands are in `WINDOWS.txt`.

The host harness sets Windows stdin and stdout to binary mode before `fread` and `fwrite`. A local `clang.exe` wrapper that force-includes `_setmode` is not part of this package and should be removed from `PATH`.

`cfg_sandbox.py` is a separate guest, not a wider leaf scanner. It accepts an explicit direct `call rel32` and a forward conditional branch, with step, depth, and trip budgets and an isolated stack. Indirect calls, backward branches, recursion, unknown targets, and missing imports are rejected. Discovery assigns every `.pdata` entry one disposition. `--diagnose` reports pointer provenance and does not execute. `--execute` runs only a closed graph that keeps its stack and callee-saved registers and does not touch untracked or writable global memory. The one real closed graph is rejected and is not treated as success. `guest_mem.c` is a sparse data map with checked access and DIR64; it does not create an executable host page. A `.pdata` entry is not eligibility. The leaf scanner still rejects `call` and `jcc`.

## AArch64

`test_aarch64_qemu.py` cross-compiles lifted `push`/`pop`, a sign-extending stack store, and `test eax, imm` with `clang --target=aarch64-linux-gnu -nostdinc` and runs those ELFs under `qemu-aarch64-static`. That is QEMU user-mode on the build machine. It is not a physical ARM64 device, not Android, and not Adreno. The game executable is not involved. Host C library headers for AArch64 are still absent; the freestanding path defines its own types.
