# AE 1.6.1170 checkpoint

This is not a playable port. The 2011 pipeline is unchanged. Nothing here calls `SkyrimSE.exe`.

## Done

- Allowlisted x64 snippets, compared with Unicorn. One `push`/`pop` snippet also ran under QEMU user-mode. That is not Android and not Adreno.
- Leaf scan of the real image, on the owner's PC: run 6 found 215 straight-line leaves, 860 cases, no divergence. No real XMM leaf was selected. Report cap and execute cap are independent. The logical map was checked separately: 20 intervals cover `SizeOfImage` 59179008 with no entry, import, relocation, TLS, or unwind execution.
- `sub rsp, imm` / `add rsp, imm` with a proven frame, flag results, and 16-byte alignment recorded from an entry RSP that is 8 mod 16. Calls, branches, and accesses outside that frame stay rejected.
- `lea r64/r32, [base+disp]`, `[rsp+disp]`, and `[rip+disp]` without a memory read. Indexed LEA stays rejected.
- Logical RVA intervals for the 59 MiB `SizeOfImage`: file-backed, zero-fill, unmapped gaps, section permissions. No guest allocation and no copy of section bytes. Dense `map_synthetic` is still capped at 1 MiB. Imports, TLS callbacks, unwind, and the entry point are recorded as not run.

## Critical path

Mapping data is not execution. There is no APK and no claim that the game runs.

1. **Runtime.** `guest_mem` holds sparse data pages. A failed map or DIR64 application leaves the previous bytes unchanged. Spans on one page keep their own read/write flags, so a writable neighbor does not widen a read-only span, and logical execute is not a host-executable page. `pe_data_map` reads a PE32+ file in place, maps sections and zero-fill, records imports as unresolved, and does not call the entry point. The cap is 64 MiB, which covers the 59 MiB image and refuses a hostile `SizeOfImage`.
2. **Translation.** Run 9 diagnosed the only closed graph and did not execute it. The callee at RVA 4271568 stores 8 bytes through incoming `RCX` at RVA 4271587. The caller is RVA 4272192. Provenance is `incoming_unspecified`, not a lost or dangling stack pointer. The 8-byte width is not an object layout, and no contract was invented. That graph stays blocked until a real caller analysis supplies size, readable, writable, and initial bytes.
3. **ABI and imports.** Import names are inventoried and left unresolved. Binding `kernel32` file, heap, and thread comes after a translated call, and still does not call the EXE entry.
4. **Renderer.** D3D11/Vulkan and Android packaging wait on that call. The launcher UI waits with them.

`call [reg]`, `call [rip]`, backward branches, and `and reg, imm` stay unsupported.

`sub rsp` will not by itself turn the 83,790 prologue rejects into running functions. Most of those functions also contain a call or a branch.
