# AE 1.6.1170 checkpoint

This is not a playable port. The 2011 pipeline is unchanged. Nothing here calls `SkyrimSE.exe`.

## Done

- Allowlisted x64 snippets, compared with Unicorn. One `push`/`pop` snippet also ran under QEMU user-mode. That is not Android and not Adreno.
- Leaf scan of the real image, on the owner's PC: run 6 found 215 straight-line leaves, 860 cases, no divergence. No real XMM leaf was selected. Report cap and execute cap are independent. The logical map was checked separately: 20 intervals cover `SizeOfImage` 59179008 with no entry, import, relocation, TLS, or unwind execution.
- `sub rsp, imm` / `add rsp, imm` with a proven frame, flag results, and 16-byte alignment recorded from an entry RSP that is 8 mod 16. Calls, branches, and accesses outside that frame stay rejected.
- `lea r64/r32, [base+disp]`, `[rsp+disp]`, and `[rip+disp]` without a memory read. Indexed LEA stays rejected.
- Logical RVA intervals for the 59 MiB `SizeOfImage`: file-backed, zero-fill, unmapped gaps, section permissions. No guest allocation and no copy of section bytes. Dense `map_synthetic` is still capped at 1 MiB. Imports, TLS callbacks, unwind, and the entry point are recorded as not run.

## Not done, in order

1. `mov [rsp+disp], imm/reg` at 8/16/32/64 bits and `movaps` with a 16-byte alignment check are in the lifter. A pointer is dereferenced only when this leaf computed it from the frame. Incoming argument registers are not a sandbox. Game leaves that contain `call` stay rejected.
2. A synthetic caller/callee sum is checked against Unicorn and, when QEMU is present, the same C model on AArch64. It does not call a Windows import. The leaf scanner still rejects `call`.
3. Run 8 assessed the only real closed graph (38+52 bytes, one direct call) and rejected it as `sandbox_untracked`. Zero graphs and zero cases ran. That rejection stands. `--diagnose` reports the RVA, width, register role, and whether the pointer is an incoming argument or stack provenance that a call dropped. It does not execute. A synthetic argument object is a declared test input with an explicit size; the access width is not turned into a layout, and it is not the game's memory. `guest_mem.c` is a sparse data map with checked reads, writes, zero-fill, and DIR64. It does not create an executable host page and does not call x64 code. `call [reg]`, `call [rip]`, backward branches, and `and reg, imm` stay unsupported.
4. Bind non-graphics imports (`kernel32` file/heap/thread) to the existing host shims. The EXE entry point stays uncalled.
5. D3D11/Vulkan and Android packaging come after a translated call works. The launcher UI waits on that.

`sub rsp` will not by itself turn the 83,790 prologue rejects into running functions. Most of those functions also contain a call or a branch.
