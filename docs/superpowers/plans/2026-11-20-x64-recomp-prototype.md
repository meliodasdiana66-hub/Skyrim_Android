# x64 recompilation prototype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated, testable x64 static-recompilation prototype that inspects PE32+ headers and lifts only synthetic instruction fixtures, checked against Unicorn x86-64.

**Architecture:** New code lives under `tools/x64/` and does not call `tools/lift.py` or the 32-bit PE loader. `inspect_pe32plus.py` accepts only AMD64/PE32+ and reads the 64-bit optional header. `lift64.py` emits a C snippet for an allowlisted instruction set and rejects everything else, including `LOCK`. `difftest64.py` compiles that C with the host clang and compares registers, flags, and memory with Unicorn. Guest memory is a 64 KiB identity map at address 0, which is enough for synthetic fixtures and too small for `ImageBase 0x140000000`.

**Tech Stack:** Python 3.12, capstone 5.0.7 (installed; README pin was 5.0.9), unicorn 2.0.1.post1, clang 18, stdlib PE parser (no `pefile`).

## Global Constraints

- Do not modify the Legendary Edition pipeline (`tools/lift.py`, `tools/discover.py`, `runtime/`, `android/`).
- Do not download, commit, or disassemble `SkyrimSE.exe` or any BSA/ESM/Data file.
- Do not decode a PE32+ optional header with PE32 offsets (`ImageBase` at +28, import directory at +104).
- Fail closed: unknown opcodes, prefixes, and `LOCK` raise and emit no runnable snippet.
- `LOCK`/atomics stay unsupported unless a test shows host results match Unicorn; this milestone rejects them.
- Do not disassemble the entry point. A `.bind` section is reported as a section only.
- Synthetic agreement with Unicorn is not game compatibility and is not an APK.
- Do not record desktop filesystem timestamps from the owner's PE notes.

---

### Task 1: PE32+ inspector

**Files:**
- Create: `tools/x64/inspect_pe32plus.py`
- Test: `tools/x64/test_proto.py`

**Interfaces:**
- Produces: `inspect_bytes(data: bytes) -> dict`, `PeFormatError`, CLI `inspect_pe32plus.py PATH [--json] [--expect-sha256 HEX]`

- [x] Write tests: PE32 and non-AMD64 rejected; ImageBase `0x140000000` not the 32-bit field; decoy import at the PE32 directory slot ignored; entry-point bytes absent from the report; `.bind` note does not claim encryption state.
- [x] Run tests and confirm they fail because the module is missing.
- [x] Implement the stdlib parser and CLI.

### Task 2: Allowlisted lifter and Unicorn differential test

**Files:**
- Create: `tools/x64/snippet_rt.h`, `tools/x64/lift64.py`, `tools/x64/difftest64.py`
- Test: `tools/x64/test_proto.py`

**Interfaces:**
- Produces: `lift_snippet(code: bytes, base: int) -> str`, `Unsupported`, `compare(code, base, cpu, mem) -> None`

- [x] Write tests for zero-extension, R8–R15, RIP-relative load/store, flag-defining ALU, flag preservation, memory side effects, and rejection of `LOCK`, `syscall`, high-byte registers, and an `MZ` image.
- [x] Run tests and confirm failure before the lifter exists.
- [x] Emit C, compile with clang `-O2`, compare to Unicorn. Skip AF only when a logical op leaves it undefined. Reject `LOCK` with no partial emulation.

### Task 3: Docs, LE regression, fixture CLI

**Files:**
- Create: `tools/x64/README.md`, `tools/x64/fixtures/mov_eax_imm.json`, `tools/x64/run_tests.sh`
- Test: LE `py_compile` plus source assertions that `tools/lift.py` stays `CS_MODE_32`

- [x] Document supported and unsupported opcodes, the 64 KiB window, and the later leaf-function procedure.
- [x] Run `tools/x64/run_tests.sh` and record results.
- [x] Confirm `git diff` against `main` does not touch `runtime/`, `android/`, or `tools/lift.py`.
