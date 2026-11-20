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

1. **Runtime.** Run 10 mapped the real image at its preferred base: 14447 pages, 37156352 file-backed bytes, 22018560 zero-fill bytes, 4096 bytes left unmapped, 9 sections, 31 import descriptors, `entryCalled` false. Logical execute is now a per-page span update, not a per-byte walk. Alternate-base DIR64 is applied in the loader before the spans are sealed, including read-only targets, and a failed relocation does not leave a half-updated qword or a widened write. Public `guest_write` still cannot bypass a read-only span.
2. **Translation.** The only closed graph is still not executed. Run 9 showed an 8-byte store through incoming `RCX` at RVA 4271587. That width is not an object layout, and no contract will be invented without a separate caller analysis. Indirect calls, backward branches, and untracked memory stay rejected.
3. **ABI and imports.** Run 12's official map loaded the real image at the preferred base and at `0x150000000`: 31 DLLs, 599 symbols, 169254 DIR64 of which 133252 are read-only, entry not called, IAT not bound. The registry on that image models exactly two imports, `GetLastError` (thunk 65599) and `GetCurrentProcessId` (thunk 65669). `SetLastError` is not imported. The other 597 imports, including Steam, stay unimplemented. `--bind-iat` is opt-in and writes guest tokens before the seal. A token is not a host pointer and not an executable page. The interpreter accepts only a registered token, checks the Windows x64 shadow and alignment, and compares a synthetic call with the same virtual shim. The default map remains unbound. The 38+52-byte `RCX` graph is still blocked.
4. **Renderer.** D3D11/Vulkan and Android packaging wait on that call. The launcher UI waits with them.

`call [reg]`, `call [rip]`, backward branches, and `and reg, imm` stay unsupported.

`sub rsp` will not by itself turn the 83,790 prologue rejects into running functions. Most of those functions also contain a call or a branch.
