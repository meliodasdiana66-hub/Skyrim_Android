#!/usr/bin/env python3
"""Tests for the isolated x64 prototype. Synthetic bytes only; no game image."""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import decode_allow  # noqa: E402
import difftest64  # noqa: E402
import inspect_pe32plus  # noqa: E402
import lift64  # noqa: E402


MEMSZ = 0x10000
BASE = 0x4000


def cpu(**regs):
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    r = [0] * 16
    flags = {"cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}
    for name, value in regs.items():
        if name in flags:
            flags[name] = int(value)
        else:
            r[names.index(name)] = int(value) & 0xFFFFFFFFFFFFFFFF
    return {"r": r, **flags}


def mem_with(code, base, patches=None):
    buf = bytearray(MEMSZ)
    buf[base:base + len(code)] = code
    for addr, data in (patches or {}).items():
        buf[addr:addr + len(data)] = data
    return buf


def check(code, base, state, patches=None, compare_af=True):
    image = mem_with(code, base, patches)
    difftest64.compare(code, base, state, image, compare_af=compare_af)


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def cstr(s):
    return s.encode("ascii") + b"\0"


def build_pe(machine=0x8664, magic=0x20B, image_base=0x140000000, stamp=0x65A5F4D5):
    """Tiny AMD64 PE32+ with a decoy at the PE32 import-directory slot."""
    e_lfanew = 0x80
    opt_size = 0xF0
    nsec = 5
    data = bytearray(0x1000)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = u32(e_lfanew)
    pe = e_lfanew
    data[pe:pe + 4] = b"PE\0\0"
    fh = pe + 4
    data[fh:fh + 2] = u16(machine)
    data[fh + 2:fh + 4] = u16(nsec)
    data[fh + 4:fh + 8] = u32(stamp)
    data[fh + 16:fh + 18] = u16(opt_size)
    data[fh + 18:fh + 20] = u16(0x22)
    opt = fh + 20
    data[opt:opt + 2] = u16(magic)
    data[opt + 16:opt + 20] = u32(0x1000)  # entry RVA, bytes not decoded
    if magic == 0x20B:
        data[opt + 24:opt + 32] = u64(image_base)
    else:
        data[opt + 28:opt + 32] = u32(image_base & 0xFFFFFFFF)
    data[opt + 32:opt + 36] = u32(0x1000)
    data[opt + 36:opt + 40] = u32(0x200)
    data[opt + 56:opt + 60] = u32(0x6000)
    data[opt + 60:opt + 64] = u32(0x400)
    data[opt + 68:opt + 70] = u16(2)
    # PE32 import directory overlaps PE32+ LoaderFlags (+104) and
    # NumberOfRvaAndSizes (+108). Point that slot at the decoy descriptor.
    data[opt + 104:opt + 108] = u32(0x2200)
    data[opt + 108:opt + 112] = u32(16)
    if magic == 0x20B:
        data[opt + 120:opt + 124] = u32(0x2000)  # real import directory
        data[opt + 124:opt + 128] = u32(40)
        data[opt + 112 + 3 * 8:opt + 112 + 3 * 8 + 4] = u32(0x3000)  # exception
        data[opt + 112 + 3 * 8 + 4:opt + 112 + 3 * 8 + 8] = u32(12)

    def section(index, name, va, raw_ptr, raw_size, chars):
        off = opt + opt_size + index * 40
        data[off:off + 8] = name.encode("ascii")[:8].ljust(8, b"\0")
        data[off + 8:off + 12] = u32(0x20)
        data[off + 12:off + 16] = u32(va)
        data[off + 16:off + 20] = u32(raw_size)
        data[off + 20:off + 24] = u32(raw_ptr)
        data[off + 36:off + 40] = u32(chars)

    section(0, ".text", 0x1000, 0x400, 0x200, 0x60000020)
    section(1, ".rdata", 0x2000, 0x600, 0x400, 0x40000040)
    section(2, ".pdata", 0x3000, 0xA00, 0x200, 0x40000040)
    section(3, ".text", 0x4000, 0xC00, 0x200, 0xC0000040)
    section(4, ".bind", 0x5000, 0xE00, 0x200, 0x60000000)
    data[0x400:0x402] = b"\xcc\xcc"  # entry-point bytes that must not be disassembled
    # Real import descriptor at RVA 0x2000, name KERNEL32.dll, one ordinal thunk.
    data[0x600:0x604] = u32(0x2060)
    data[0x60C:0x610] = u32(0x2080)
    data[0x610:0x614] = u32(0x2060)
    data[0x660:0x668] = u64(0x8000000000000001)
    data[0x680:0x680 + 13] = cstr("KERNEL32.dll")
    # Decoy descriptor at RVA 0x2200 named DECOY32.DLL.
    data[0x800:0x804] = u32(0x2260)
    data[0x80C:0x810] = u32(0x2280)
    data[0x810:0x814] = u32(0x2260)
    data[0x860:0x868] = u64(0x8000000000000002)
    data[0x880:0x880 + 12] = cstr("DECOY32.DLL")
    return bytes(data)


class Pe32PlusTests(unittest.TestCase):
    def test_rejects_pe32_magic_even_on_amd64(self):
        blob = build_pe(magic=0x10B, image_base=0x400000)
        with self.assertRaises(inspect_pe32plus.PeFormatError) as caught:
            inspect_pe32plus.inspect_bytes(blob)
        self.assertIn("PE32+", str(caught.exception))
        self.assertIn("0x10B", str(caught.exception))

    def test_rejects_non_amd64(self):
        blob = build_pe(machine=0x14C)
        with self.assertRaises(inspect_pe32plus.PeFormatError) as caught:
            inspect_pe32plus.inspect_bytes(blob)
        self.assertIn("0x8664", str(caught.exception))

    def test_image_base_and_imports_use_pe32plus_layout(self):
        info = inspect_pe32plus.inspect_bytes(build_pe())
        self.assertEqual(info["imageBase"], 0x140000000)
        self.assertEqual(info["magic"], "PE32+")
        self.assertEqual(info["machine"], "IMAGE_FILE_MACHINE_AMD64")
        self.assertEqual(info["addressOfEntryPoint"], 0x1000)
        self.assertFalse(info["entryPointDisassembled"])
        dlls = [row["dll"] for row in info["imports"]]
        self.assertEqual(dlls, ["KERNEL32.dll"])
        self.assertNotIn("DECOY32.DLL", dlls)
        self.assertEqual(info["imports"][0]["count"], 1)
        names = [s["name"] for s in info["sections"]]
        self.assertEqual(names.count(".text"), 2)
        self.assertTrue(info["bindSection"]["present"])
        self.assertTrue(info["pdataSection"]["present"])
        self.assertTrue(info["exceptionDirectory"]["present"])
        self.assertIn("not", info["bindSection"]["note"].lower())
        blob = json.dumps(info)
        self.assertNotIn("int3", blob)
        self.assertNotIn("disasm", blob.lower())
        self.assertNotIn("cccc", blob.lower())

    def test_cli_sha256_and_json(self):
        blob = build_pe()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.exe"
            path.write_bytes(blob)
            digest = inspect_pe32plus.sha256_hex(blob)
            bad = subprocess.run(
                [sys.executable, str(HERE / "inspect_pe32plus.py"), str(path),
                 "--json", "--expect-sha256", "00" * 32],
                capture_output=True, text=True, check=False)
            self.assertEqual(bad.returncode, 3)
            good = subprocess.run(
                [sys.executable, str(HERE / "inspect_pe32plus.py"), str(path),
                 "--json", "--expect-sha256", digest],
                capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0, good.stderr)
            got = json.loads(good.stdout)
            self.assertEqual(got["imageBase"], 0x140000000)
            self.assertEqual(got["size"], len(blob))


class LiftTests(unittest.TestCase):
    def test_mov_r32_zero_extends(self):
        code = bytes.fromhex("b8ffffffff")  # mov eax, 0xffffffff
        state = cpu(rax=0xFFFFFFFFFFFFFFFF, cf=1, zf=1)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0xFFFFFFFF)
        self.assertEqual(got["cf"], 1)
        self.assertEqual(got["zf"], 1)

    def test_mov_r16_preserves_upper_bits(self):
        code = bytes.fromhex("66b83412")  # mov ax, 0x1234
        state = cpu(rax=0xFFFFFFFFFFFFFFFF)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0xFFFFFFFFFFFF1234)

    def test_mov_r8_preserves_upper_bits(self):
        code = bytes.fromhex("b012")  # mov al, 0x12
        state = cpu(rax=0xFFFFFFFFFFFFFFFF, cf=1, zf=1)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0xFFFFFFFFFFFFFF12)

    def test_xor_eax_zero_extends_and_sets_zf(self):
        code = bytes.fromhex("31c0")  # xor eax, eax
        # AF is undefined for XOR. The lifter leaves it unchanged and the
        # differential comparison skips it instead of treating a guess as proof.
        state = cpu(rax=0x1122334455667788, af=1)
        check(code, BASE, state, compare_af=False)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0)
        self.assertEqual(got["zf"], 1)
        self.assertEqual(got["cf"], 0)
        self.assertEqual(got["of"], 0)
        self.assertEqual(got["af"], 1)

    def test_add_eax_one_wraps_32bit_flags(self):
        code = bytes.fromhex("83c001")  # add eax, 1
        state = cpu(rax=0xFFFFFFFF)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0)
        self.assertEqual(got["cf"], 1)
        self.assertEqual(got["zf"], 1)
        self.assertEqual(got["of"], 0)

    def test_sub_r32_zero_extends(self):
        code = bytes.fromhex("29c8")  # sub eax, ecx
        state = cpu(rax=0xAAAAAAAA00000005, rcx=3)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 2)

    def test_r8_through_r11(self):
        # movabs r8, imm; mov r9, r8; add r10, r11
        code = bytes.fromhex("49b888776655443322114d89c14d01da")
        state = cpu(r10=10, r11=32)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][8], 0x1122334455667788)
        self.assertEqual(got["r"][9], 0x1122334455667788)
        self.assertEqual(got["r"][10], 42)

    def test_rip_relative_load_and_store(self):
        # mov rax, [rip+disp]; mov rbx, rax; add rax, rbx; mov [rip+disp2], rax
        load_at = BASE
        load = b"\x48\x8b\x05" + struct.pack("<i", 0x6000 - (load_at + 7))
        mov_rbx = b"\x48\x89\xc3"
        add = b"\x48\x01\xd8"
        store_at = load_at + len(load) + len(mov_rbx) + len(add)
        store = b"\x48\x89\x05" + struct.pack("<i", 0x6100 - (store_at + 7))
        code = load + mov_rbx + add + store
        image_patches = {0x6000: struct.pack("<Q", 0x20)}
        state = cpu()
        check(code, BASE, state, image_patches)
        got_cpu, got_mem = difftest64.run_both(code, BASE, state, mem_with(code, BASE, image_patches))
        self.assertEqual(got_cpu["r"][0], 0x40)
        self.assertEqual(struct.unpack_from("<Q", got_mem, 0x6100)[0], 0x40)
        self.assertEqual(struct.unpack_from("<Q", got_mem, 0x6000)[0], 0x20)

    def test_register_indirect_memory(self):
        # mov [rax], rbx; mov rcx, [rax]
        code = bytes.fromhex("488918488b08")
        state = cpu(rax=0x6200, rbx=0x99)
        check(code, BASE, state)
        got_cpu, got_mem = difftest64.run_both(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got_cpu["r"][1], 0x99)
        self.assertEqual(struct.unpack_from("<Q", got_mem, 0x6200)[0], 0x99)

    def test_add_r64_overflow_flags(self):
        code = bytes.fromhex("4801d8")  # add rax, rbx
        state = cpu(rax=0x7FFFFFFFFFFFFFFF, rbx=1)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0x8000000000000000)
        self.assertEqual(got["of"], 1)
        self.assertEqual(got["sf"], 1)
        self.assertEqual(got["cf"], 0)

    def test_cmp_sets_cf_without_writing_dest(self):
        code = bytes.fromhex("4839d8")  # cmp rax, rbx
        state = cpu(rax=1, rbx=2)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 1)
        self.assertEqual(got["cf"], 1)
        self.assertEqual(got["zf"], 0)

    def test_movzx_zero_extends(self):
        code = bytes.fromhex("0fb6c0")  # movzx eax, al
        state = cpu(rax=0xFFFFFFFFFFFFFFFF)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0xFF)

    def test_nop_preserves_state(self):
        code = b"\x90"
        state = cpu(rax=5, cf=1, zf=1)
        check(code, BASE, state)

    def test_final_ret_is_not_executed(self):
        # mov eax, 1; ret. RSP is 0 and the first bytes are a canary. Executing
        # ret would pop that canary and change RSP.
        code = bytes.fromhex("b801000000c3")
        image = mem_with(code, BASE)
        image[0:8] = b"CANARY!!"
        state = cpu(rsp=0, rax=0xFFFFFFFFFFFFFFFF)
        check(code, BASE, state)
        got_cpu, got_mem = difftest64.run_both(code, BASE, state, image)
        self.assertEqual(got_cpu["r"][0], 1)
        self.assertEqual(got_cpu["r"][4], 0)
        self.assertEqual(bytes(got_mem[0:8]), b"CANARY!!")

    def test_ret_in_the_middle_and_ret_imm_are_rejected(self):
        with self.assertRaises(lift64.Unsupported):
            lift64.lift_snippet(bytes.fromhex("b801000000c390"), BASE)
        with self.assertRaises(lift64.Unsupported):
            lift64.lift_snippet(bytes.fromhex("c20000"), BASE)

    def test_push_pop_round_trip_and_imm(self):
        code = bytes.fromhex("5059")  # push rax; pop rcx
        state = cpu(rax=0x1122334455667788, rsp=0xE000)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][1], 0x1122334455667788)
        self.assertEqual(got["r"][4], 0xE000)
        neg = bytes.fromhex("6aff58")  # push -1; pop rax
        state = cpu(rax=0, rsp=0xE000)
        check(neg, BASE, state)
        got = difftest64.run_host(neg, BASE, state, mem_with(neg, BASE))
        self.assertEqual(got["r"][0], 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(got["r"][4], 0xE000)

    def test_rsp_relative_slot_after_push(self):
        # push rbx; mov rax, [rsp]; mov [rsp+0], rcx is not this snippet.
        # push rbx; mov rax, qword ptr [rsp]
        code = bytes.fromhex("53488b0424")
        state = cpu(rbx=0x0102030405060708, rsp=0xE000, cf=1)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0x0102030405060708)
        self.assertEqual(got["r"][4], 0xDFF8)
        self.assertEqual(got["cf"], 1)

    def test_sub_rsp_immediate_flags_and_alignment(self):
        # sub rsp, 0x28 from an entry-like RSP (8 mod 16) lands 0 mod 16.
        code = bytes.fromhex("4883ec28")
        state = cpu(rsp=0xE008, cf=1)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][4], 0xDFE0)
        self.assertEqual(got["r"][4] % 16, 0)
        self.assertEqual(got["cf"], 0)
        # sub rsp, 0x20 stays 8 mod 16. The instruction is still valid.
        narrow = bytes.fromhex("4883ec20")
        state = cpu(rsp=0xE008)
        check(narrow, BASE, state)
        got = difftest64.run_host(narrow, BASE, state, mem_with(narrow, BASE))
        self.assertEqual(got["r"][4] % 16, 8)
        # sub rax, 1 borrows.
        borrow = bytes.fromhex("4883e801")
        state = cpu(rax=0)
        check(borrow, BASE, state)
        got = difftest64.run_host(borrow, BASE, state, mem_with(borrow, BASE))
        self.assertEqual(got["r"][0], 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(got["cf"], 1)

    def test_stack_immediate_store_sign_and_partial(self):
        # qword store sign-extends imm32. Neighbouring bytes are not this test's subject.
        code = bytes.fromhex("48c7042400000080")  # mov qword [rsp], 0x80000000
        state = cpu(rsp=0xE000)
        image = mem_with(code, BASE)
        image[0xE000:0xE008] = b"\x11" * 8
        check(code, BASE, state, None)
        # check() rebuilds memory, so set the pattern on the image passed to run_both
        image = mem_with(code, BASE)
        image[0xE000:0xE008] = b"\x11" * 8
        got_cpu, got_mem = difftest64.run_both(code, BASE, state, image)
        self.assertEqual(got_mem[0xE000:0xE008], bytes.fromhex("00000080ffffffff"))
        partial = bytes.fromhex("c7042478563412")  # mov dword [rsp], 0x12345678
        image = mem_with(partial, BASE)
        image[0xE000:0xE008] = b"\xff" * 8
        _cpu, got_mem = difftest64.run_both(partial, BASE, state, image)
        self.assertEqual(got_mem[0xE000:0xE008], bytes.fromhex("78563412ffffffff"))

    def test_movaps_alignment(self):
        state = cpu(rsp=0xE000)
        state["xmm"] = [0x112233445566778899aabbccddeeff00] + [0] * 15
        aligned = bytes.fromhex("0f290424")  # movaps [rsp], xmm0
        image = mem_with(aligned, BASE)
        got_cpu, got_mem = difftest64.run_both(aligned, BASE, state, image)
        self.assertEqual(got_mem[0xE000:0xE010], (0x112233445566778899aabbccddeeff00).to_bytes(16, "little"))
        self.assertEqual(got_cpu["xmm"][0], state["xmm"][0])
        bad = bytes.fromhex("0f29442408")  # movaps [rsp+8], xmm0
        image = mem_with(bad, BASE)
        with self.assertRaises(RuntimeError):
            difftest64.exec_host(bad, BASE, state, image)
        # This Unicorn build executes unaligned MOVAPS. The host aborts, and the
        # leaf scanner rejects the address before a comparison is attempted.
        difftest64.exec_unicorn(bad, BASE, state, image)

    def test_lea_forms_do_not_read_memory(self):
        # lea rax, [rcx+8]; flags stay set; memory unchanged.
        code = bytes.fromhex("488d4108")
        state = cpu(rcx=0x10, cf=1, zf=1)
        image = mem_with(code, BASE)
        image[0x18:0x20] = b"\xff" * 8
        check(code, BASE, state)
        got_cpu, got_mem = difftest64.run_both(code, BASE, state, image)
        self.assertEqual(got_cpu["r"][0], 0x18)
        self.assertEqual(got_cpu["cf"], 1)
        self.assertEqual(got_cpu["zf"], 1)
        self.assertEqual(bytes(got_mem[0x18:0x20]), b"\xff" * 8)
        # 32-bit lea zero-extends.
        code = bytes.fromhex("8d4101")
        state = cpu(rax=0xFFFFFFFFFFFFFFFF, rcx=0xFFFFFFFFFFFFFFFF)
        check(code, BASE, state)
        got = difftest64.run_host(code, BASE, state, mem_with(code, BASE))
        self.assertEqual(got["r"][0], 0)
        with self.assertRaises(decode_allow.Reject):
            decode_allow.decode_stream(bytes.fromhex("488d0458"), BASE)  # lea rax, [rax+rbx*2]

    def test_push_rsp_and_call_stay_rejected(self):
        with self.assertRaises(lift64.Unsupported):
            lift64.lift_snippet(bytes.fromhex("54"), BASE)
        with self.assertRaises(decode_allow.Reject) as caught:
            decode_allow.decode_stream(bytes.fromhex("54"), BASE)
        self.assertEqual(caught.exception.reason, "push_rsp")
        with self.assertRaises(decode_allow.Reject) as caught:
            decode_allow.decode_stream(bytes.fromhex("e800000000"), BASE)
        self.assertEqual(caught.exception.reason, "call")

    def test_test_immediate_keeps_dest_and_sets_logic_flags(self):
        cases = (
            (bytes.fromhex("a9ff000000c3"), 0, 1, 1, 0),
            (bytes.fromhex("a9ff000000c3"), 1, 0, 0, 0),
            (bytes.fromhex("a900000080c3"), 0x80000000, 0, 1, 1),
        )
        for code, eax, zf, pf, sf in cases:
            got, _out = difftest64.run_both(code, BASE, cpu(rax=eax), mem_with(code, BASE), compare_af=False)
            self.assertEqual(got["r"][0], eax)
            self.assertEqual((got["zf"], got["pf"], got["sf"], got["cf"], got["of"]), (zf, pf, sf, 0, 0))

    def test_binary_stdio_preserves_ctrl_z_and_crlf(self):
        src = difftest64.host_source("void snippet(Cpu64 *c, uint8_t *mem) { (void)c; (void)mem; }\n")
        self.assertLess(src.find("_setmode"), src.find("fread"))
        self.assertIn("_O_BINARY", src)
        state = cpu(rax=0x1A0D0A1A)
        state["xmm"] = [0x1A] + [0] * 15
        image = mem_with(b"\x90", BASE)
        image[0x5000:0x5004] = b"\x1a\r\n\x1a"
        got, out = difftest64.run_both(b"\x90", BASE, state, image)
        self.assertEqual(got["r"][0], 0x1A0D0A1A)
        self.assertEqual(got["xmm"][0], 0x1A)
        self.assertEqual(bytes(out[0x5000:0x5004]), b"\x1a\r\n\x1a")

    def test_lock_is_rejected(self):
        code = bytes.fromhex("f0480118")  # lock add qword ptr [rax], rbx
        with self.assertRaises(lift64.Unsupported) as caught:
            lift64.lift_snippet(code, BASE)
        self.assertIn("lock", str(caught.exception).lower())

    def test_syscall_and_high_byte_rejected(self):
        with self.assertRaises(lift64.Unsupported):
            lift64.lift_snippet(bytes.fromhex("0f05"), BASE)
        with self.assertRaises(lift64.Unsupported) as caught:
            lift64.lift_snippet(bytes.fromhex("b401"), BASE)  # mov ah, 1
        self.assertIn("ah", str(caught.exception).lower())

    def test_refuses_pe_image_and_address_size_prefix(self):
        with self.assertRaises(lift64.Unsupported) as caught:
            lift64.lift_snippet(b"MZ" + b"\x90" * 8, BASE)
        self.assertIn("PE", str(caught.exception))
        with self.assertRaises(lift64.Unsupported):
            lift64.lift_snippet(bytes.fromhex("678b00"), BASE)  # addr32 mov eax, [eax]

    def test_fixture_cli(self):
        proc = subprocess.run(
            [sys.executable, str(HERE / "difftest64.py"),
             "--fixture", str(HERE / "fixtures" / "mov_eax_imm.json")],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("match", proc.stdout.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
