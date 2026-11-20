#!/usr/bin/env python3
"""Real call [rip+disp32] through a guest IAT token. Not a game launch."""
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

import cfg_sandbox  # noqa: E402

DONE = 0x5000
RSP = 0xE008
ENTRY = 0x4000
IAT_SET = 0x2100
IAT_GET = 0x2108
IAT_EXIT = 0x2110
LAST = 0x2200
PID = 0xABCD


def _cpu():
    regs = [0] * 16
    regs[0] = 0x111
    regs[1] = 0x22
    regs[3] = 0xA11CE
    regs[4] = RSP
    return {"r": regs, "cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}


def _mem():
    buf = bytearray(cfg_sandbox.MEMSZ)
    buf[RSP:RSP + 8] = struct.pack("<Q", DONE)
    buf[LAST:LAST + 4] = struct.pack("<I", 0x55)
    return buf


def _rel(at, target):
    return struct.pack("<i", target - (at + 6))


def _call(at, slot):
    return b"\xff\x15" + _rel(at, slot)


def _program():
    code = bytes.fromhex("b922000000") + bytes.fromhex("4883ec28")
    at = ENTRY + len(code)
    code += _call(at, IAT_SET)
    at = ENTRY + len(code)
    code += _call(at, IAT_GET)
    code += bytes.fromhex("4883c428") + b"\xc3"
    return code


def _slots():
    return {
        IAT_SET: {"id": 1, "name": "SetLastError", "modeled": True},
        IAT_GET: {"id": 2, "name": "GetLastError", "modeled": True},
        IAT_EXIT: {"id": 3, "name": "ExitProcess", "modeled": False},
    }


def _plant(buf, slots):
    for addr, slot in slots.items():
        kind = 1 if slot["modeled"] else 2
        buf[addr:addr + 8] = struct.pack("<Q", cfg_sandbox.guest_token(kind, slot["id"]))


class IatLiftTests(unittest.TestCase):
    def test_overlap_and_image_bounds_fail_closed(self):
        self.assertIsNone(cfg_sandbox.iat_slot_fault(0x2FF8, 0x3000))
        self.assertEqual(cfg_sandbox.iat_slot_fault(0x3000, 0x3000), "iat_oob")
        self.assertEqual(cfg_sandbox.iat_slot_fault(0x2FFC, 0x3000), "iat_cross_page")
        code = bytes.fromhex("90c3")
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({cfg_sandbox.STACK_LO: code}, cfg_sandbox.STACK_LO, _cpu(), _mem(), DONE, {}, LAST, PID)
        self.assertEqual(caught.exception.reason, "range_overlap")
        slots = {0xE000: {"id": 2, "name": "GetLastError", "modeled": True}}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: code}, ENTRY, _cpu(), _mem(), DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "range_overlap")
        covering = b"\x90" * 0x20 + b"\xc3"
        slots = {0x2100: {"id": 2, "name": "GetLastError", "modeled": True}}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({0x20E8: covering}, 0x20E8, _cpu(), _mem(), DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "range_overlap")

    def test_image_rva_is_not_a_snippet_window_fault(self):
        real = 24441520
        self.assertIsNone(cfg_sandbox.iat_slot_fault(real, 59179008))
        self.assertEqual(cfg_sandbox.iat_slot_fault(real, cfg_sandbox.MEMSZ), "iat_oob")
        self.assertEqual(cfg_sandbox.iat_slot_fault(0x1FFC, 59179008), "iat_cross_page")
        self.assertEqual(cfg_sandbox.iat_slot_fault(0xFFFFFFFFFFFFFFFC, cfg_sandbox.MAX_GUEST), "iat_oob")
        self.assertEqual(cfg_sandbox.iat_slot_fault(0, cfg_sandbox.MAX_GUEST + 1), "image_limit")
        self.assertFalse(cfg_sandbox.canonical_user(cfg_sandbox.guest_token(1, 65599)))
        self.assertTrue(cfg_sandbox.canonical_user(cfg_sandbox.STUB_BASE))

    def test_ordinal_flag_is_not_a_token(self):
        self.assertIsNone(cfg_sandbox.token_decode(0x8000000000000007))
        self.assertIsNone(cfg_sandbox.token_decode(0x8000000000000000))
        kind, thunk = cfg_sandbox.token_decode(cfg_sandbox.guest_token(1, 65599))
        self.assertEqual((kind, thunk), (1, 65599))

    def test_call_rip_matches_the_virtual_api_and_unicorn_hook(self):
        code = _program()
        insns = cfg_sandbox.decode_allow.decode_stream(code, ENTRY, control=True)
        self.assertEqual([insn["mnemonic"] for insn in insns if insn["mnemonic"] == "call_rip"], ["call_rip", "call_rip"])
        mem = _mem()
        slots = _slots()
        _plant(mem, slots)
        second_return = ENTRY + 5 + 4 + 6 + 6
        result = cfg_sandbox.execute_iat(
            {ENTRY: code}, ENTRY, _cpu(), mem, DONE, slots, LAST, PID, probe=RSP - 0x30)
        rax, last = 0x111, 0x55
        for name, ecx in (("SetLastError", 0x22), ("GetLastError", 0x22)):
            rax, last = cfg_sandbox.virtual_api(name, ecx, last, PID, rax)
        self.assertEqual(result["rax"], rax)
        self.assertEqual(result["lastError"], last)
        self.assertEqual(result["rsp"], RSP + 8)
        self.assertEqual(result["rbx"], 0xA11CE)
        self.assertEqual(result["probe"], second_return)
        self.assertEqual(result["slots"][IAT_SET], cfg_sandbox.guest_token(1, 1))
        self.assertFalse(result["entryPointExecuted"])
        self.assertEqual(result["oracle"], "unicorn-canonical-stub")
        self.assertFalse(cfg_sandbox.canonical_user(result["slots"][IAT_SET]))
        self.assertTrue(cfg_sandbox.canonical_user(cfg_sandbox.STUB_BASE))
        self.assertFalse(cfg_sandbox.canonical_user(result["slots"][IAT_SET]))
        self.assertTrue(cfg_sandbox.canonical_user(cfg_sandbox.STUB_BASE))

    def test_negative_calls_do_not_invent_a_return(self):
        slots = _slots()
        bare = _call(ENTRY, IAT_GET) + b"\xc3"
        mem = _mem()
        _plant(mem, slots)
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: bare}, ENTRY, _cpu(), mem, DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "misaligned_stack")
        self.assertEqual(caught.exception.detail["rsp"], RSP)
        self.assertEqual(caught.exception.detail["rax"], 0x111)
        self.assertEqual(caught.exception.detail["below"], 0)
        high = bytearray(_mem())
        _plant(high, slots)
        high[IAT_GET:IAT_GET + 8] = struct.pack("<Q", 0x8000000000000007)
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: _program()}, ENTRY, _cpu(), high, DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "illegal_token")
        self.assertEqual(caught.exception.detail["rsp"], RSP - 0x28)
        self.assertEqual(caught.exception.detail["below"], ENTRY + 15)
        forged = bytearray(_mem())
        _plant(forged, slots)
        forged[IAT_GET:IAT_GET + 8] = struct.pack("<Q", cfg_sandbox.guest_token(1, 99))
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: _program()}, ENTRY, _cpu(), forged, DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "illegal_token")
        unknown = _call(ENTRY, 0x3000) + b"\xc3"
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare({ENTRY: unknown}, ENTRY, iat_slots=slots)
        self.assertEqual(caught.exception.reason, "unknown_iat")
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare({ENTRY: _call(ENTRY, IAT_GET) + b"\xc3"}, ENTRY)
        self.assertEqual(caught.exception.reason, "indirect_call")
        cross = {0x1FFC: {"id": 1, "name": "GetLastError", "modeled": True}}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare({ENTRY: _call(ENTRY, 0x1FFC) + b"\xc3"}, ENTRY, iat_slots=cross)
        self.assertEqual(caught.exception.reason, "iat_cross_page")
        exit_code = bytes.fromhex("4883ec28") + _call(ENTRY + 4, IAT_EXIT) + b"\xc3"
        planted = _mem()
        _plant(planted, slots)
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: exit_code}, ENTRY, _cpu(), planted, DONE, slots, LAST, PID)
        self.assertEqual(caught.exception.reason, "unimplemented_import")
        self.assertEqual(caught.exception.detail["rax"], 0x111)
        self.assertEqual(caught.exception.detail["below"], 0)
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: _program()}, ENTRY, _cpu(), _mem(), DONE, slots, LAST, PID, max_depth=0)
        self.assertEqual(caught.exception.reason, "depth_budget")
        self.assertEqual(caught.exception.detail["below"], 0)
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute_iat({ENTRY: _program()}, ENTRY, _cpu(), _mem(), DONE, slots, LAST, PID, max_steps=2)
        self.assertEqual(caught.exception.reason, "step_budget")

    def test_pipeline_from_a_synthetic_pe(self):
        code = bytes.fromhex("4883ec28")
        code += _call(0x1000 + len(code), 0x2080)
        code += bytes.fromhex("4883c428") + b"\xc3"
        other = _call(0x1100, 0x2088) + b"\xc3"
        blob = bytearray(0x800)
        blob[0:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3C, 0x80)
        blob[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", blob, 0x84, 0x8664, 3)
        struct.pack_into("<H", blob, 0x94, 0xF0)
        struct.pack_into("<H", blob, 0x98, 0x20B)
        struct.pack_into("<I", blob, 0x98 + 16, 0x1F00)
        struct.pack_into("<Q", blob, 0x98 + 24, 0x140000000)
        struct.pack_into("<I", blob, 0x98 + 56, 0x4000)
        struct.pack_into("<I", blob, 0x98 + 108, 16)
        struct.pack_into("<II", blob, 0x98 + 120, 0x2000, 40)
        struct.pack_into("<II", blob, 0x98 + 136, 0x3000, 24)
        blob[0x188:0x188 + 5] = b".text"
        struct.pack_into("<IIIIII", blob, 0x188 + 8, 0x1000, 0x1000, 0x200, 0x200, 0, 0)
        struct.pack_into("<I", blob, 0x188 + 36, 0x60000020)
        blob[0x1B0:0x1B0 + 5] = b".data"
        struct.pack_into("<IIIIII", blob, 0x1B0 + 8, 0x200, 0x2000, 0x200, 0x400, 0, 0)
        struct.pack_into("<I", blob, 0x1B0 + 36, 0x40000040)
        blob[0x1D8:0x1D8 + 6] = b".pdata"
        struct.pack_into("<IIIIII", blob, 0x1D8 + 8, 0x100, 0x3000, 0x100, 0x600, 0, 0)
        struct.pack_into("<I", blob, 0x1D8 + 36, 0x40000040)
        blob[0x200:0x200 + len(code)] = code
        blob[0x300:0x300 + len(other)] = other
        struct.pack_into("<IIIII", blob, 0x400, 0x2040, 0, 0, 0x20C0, 0x2080)
        struct.pack_into("<Q", blob, 0x440, 0x2100)
        struct.pack_into("<Q", blob, 0x448, 0x2140)
        struct.pack_into("<Q", blob, 0x450, 0x8000000000000007)
        struct.pack_into("<Q", blob, 0x480, 0x2100)
        struct.pack_into("<Q", blob, 0x488, 0x2140)
        struct.pack_into("<Q", blob, 0x490, 0x8000000000000007)
        blob[0x4C0:0x4C0 + 13] = b"KERNEL32.dll"
        blob[0x502:0x502 + 20] = b"GetCurrentProcessId"
        blob[0x542:0x542 + 12] = b"ExitProcess"
        struct.pack_into("<III", blob, 0x600, 0x1000, 0x1000 + len(code), 0)
        struct.pack_into("<III", blob, 0x60C, 0x1100, 0x1100 + len(other), 0)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            path = td / "mini.bin"
            path.write_bytes(blob)
            exe = td / "dump"
            built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "ae_bind_dump.c"), str(HERE / "pe_data.c"), str(HERE / "guest_mem.c"),
                 str(HERE / "ae_abi.c"), str(HERE / "ae_dispatch.c"), str(HERE / "ae_iat.c"),
                 "-I", str(HERE), "-o", str(exe)],
                capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(exe), str(path)], capture_output=True, text=True, check=False)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(path.read_bytes(), bytes(blob))
            report = json.loads(ran.stdout)
            self.assertFalse(report["entryCalled"])
            self.assertTrue(report["importsBound"])
            self.assertFalse(report["hostExecutable"])
            pid_slot = next(row for row in report["slots"] if row["name"] == "GetCurrentProcessId")
            self.assertEqual(pid_slot["rva"], 0x2080)
            self.assertTrue(pid_slot["modeled"])
            self.assertEqual(int(pid_slot["token"], 16), cfg_sandbox.guest_token(1, 0))
            decoded = cfg_sandbox.decode_allow.decode_stream(code, 0x1000, control=True)
            self.assertEqual(decoded[1]["mnemonic"], "call_rip")
            self.assertEqual(decoded[1]["iat"], 0x2080)
            mem = _mem()
            mem[0x1000:0x1000 + len(code)] = code
            mem[0x2080:0x2088] = struct.pack("<Q", int(pid_slot["token"], 16))
            slots = {0x2080: {"id": 0, "name": "GetCurrentProcessId", "modeled": True}}
            result = cfg_sandbox.execute_iat({0x1000: code}, 0x1000, _cpu(), mem, DONE, slots, LAST, PID)
            expect, _last = cfg_sandbox.virtual_api("GetCurrentProcessId", 0, 0x55, PID, 0x111)
            self.assertEqual(result["rax"], expect)
            self.assertEqual(result["rbx"], 0xA11CE)
            self.assertEqual(result["rsp"], RSP + 8)
            found = cfg_sandbox.discover_modeled_iat(bytes(blob))
            self.assertFalse(found["executed"])
            self.assertFalse(found["entryPointExecuted"])
            self.assertEqual(found["modeledSlots"], 1)
            self.assertEqual(found["ordinalSlots"], 1)
            self.assertEqual(found["eligible"], 1)
            self.assertEqual(found["eligibleEntries"], [0x1000])
            self.assertEqual(found["obstacles"].get("iat_unmodeled"), 1)
            text = json.dumps(found)
            self.assertNotRegex(text, r"\"[0-9a-fA-F]{16,}\"")


class DiagnosticDetailTests(unittest.TestCase):
    def test_modeled_candidates_keep_every_reason_and_no_bytes(self):
        iat = 0x2100
        direct = 0x1100
        data_rva = 0x3000
        first = bytes.fromhex("4883ec28")
        first += b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(first) + 6))
        call_at = 0x1000 + len(first)
        first += b"\xe8" + struct.pack("<i", direct - (call_at + 5))
        first += bytes.fromhex("4883c428c3")
        helper = bytes.fromhex("90c3")
        second = bytes.fromhex("4883ec28")
        second += b"\xff\x15" + struct.pack("<i", iat - (0x1200 + len(second) + 6))
        mov_at = 0x1200 + len(second)
        second += b"\x48\x8b\x05" + struct.pack("<i", data_rva - (mov_at + 7))
        second += bytes.fromhex("4883c428c3")
        blob = bytearray(0xC00)
        blob[0:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3C, 0x80)
        blob[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", blob, 0x84, 0x8664, 4)
        struct.pack_into("<H", blob, 0x94, 0xF0)
        struct.pack_into("<H", blob, 0x98, 0x20B)
        struct.pack_into("<I", blob, 0x98 + 16, 0x1F00)
        struct.pack_into("<Q", blob, 0x98 + 24, 0x140000000)
        struct.pack_into("<I", blob, 0x98 + 56, 0x5000)
        struct.pack_into("<I", blob, 0x98 + 108, 16)
        struct.pack_into("<II", blob, 0x98 + 120, 0x2000, 40)
        struct.pack_into("<II", blob, 0x98 + 136, 0x4000, 36)
        blob[0x188:0x18D] = b".text"
        struct.pack_into("<IIIIII", blob, 0x188 + 8, 0x1000, 0x1000, 0x400, 0x400, 0, 0)
        struct.pack_into("<I", blob, 0x188 + 36, 0x60000020)
        blob[0x1B0:0x1B5] = b".data"
        struct.pack_into("<IIIIII", blob, 0x1B0 + 8, 0x200, 0x2000, 0x200, 0x800, 0, 0)
        struct.pack_into("<I", blob, 0x1B0 + 36, 0xC0000040)
        blob[0x1D8:0x1DE] = b".rdata"
        struct.pack_into("<IIIIII", blob, 0x1D8 + 8, 0x100, 0x3000, 0x100, 0xA00, 0, 0)
        struct.pack_into("<I", blob, 0x1D8 + 36, 0x40000040)
        blob[0x200:0x206] = b".pdata"
        struct.pack_into("<IIIIII", blob, 0x208, 0x100, 0x4000, 0x100, 0xB00, 0, 0)
        struct.pack_into("<I", blob, 0x224, 0x40000040)
        blob[0x400:0x400 + len(first)] = first
        blob[0x500:0x502] = helper
        blob[0x600:0x600 + len(second)] = second
        struct.pack_into("<IIIII", blob, 0x800, 0x2040, 0, 0, 0x2080, 0x2100)
        struct.pack_into("<Q", blob, 0x840, 0x2120)
        blob[0x880:0x88D] = b"KERNEL32.dll"
        blob[0x922:0x922 + 13] = b"GetLastError"
        struct.pack_into("<III", blob, 0xB00, 0x1000, 0x1000 + len(first), 0)
        struct.pack_into("<III", blob, 0xB0C, 0x1100, 0x1102, 0)
        struct.pack_into("<III", blob, 0xB18, 0x1200, 0x1200 + len(second), 0)
        found = cfg_sandbox.discover_modeled_iat(bytes(blob))
        self.assertEqual(found["eligibleEntries"], [0x1000])
        self.assertFalse(found["executed"])
        by_rva = {row["rva"]: row for row in found["modeledCandidates"]}
        self.assertEqual(sorted(by_rva), [0x1000, 0x1200])
        self.assertEqual(by_rva[0x1000]["reasons"], [])
        self.assertTrue(by_rva[0x1000]["closure"]["proven"])
        self.assertEqual(by_rva[0x1000]["directCallTargets"], [0x1100])
        self.assertEqual(by_rva[0x1000]["imports"][0]["name"], "GetLastError")
        self.assertTrue(by_rva[0x1000]["imports"][0]["modeled"])
        self.assertEqual(by_rva[0x1200]["reasons"], ["memory_access"])
        self.assertEqual(by_rva[0x1200]["memory"][0]["kind"], "rip")
        access = by_rva[0x1200]["memory"][0]
        self.assertEqual(access["kind"], "rip")
        self.assertEqual(access["access"], "load")
        self.assertEqual(access["width"], 8)
        self.assertEqual(access["target"], 0x3000)
        self.assertEqual(access["section"], ".rdata")
        self.assertFalse(access["writable"])
        text = json.dumps(found)
        self.assertNotIn("4883ec28", text)
        self.assertNotIn("8b05", text.lower())


class TailTransferTests(unittest.TestCase):
    def test_tail_jump_is_not_a_load_and_verifies_when_proven(self):
        iat = 0x2100
        callee = 0x1100
        code = bytes.fromhex("31c04883ec28")
        code += b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6))
        code += bytes.fromhex("4883c428")
        code += b"\xe9" + struct.pack("<i", callee - (0x1000 + len(code) + 5))
        helper = b"\xc3"
        blob = bytearray(0x800)
        blob[0:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3C, 0x80)
        blob[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", blob, 0x84, 0x8664, 3)
        struct.pack_into("<H", blob, 0x94, 0xF0)
        struct.pack_into("<H", blob, 0x98, 0x20B)
        struct.pack_into("<I", blob, 0x98 + 16, 0x1F00)
        struct.pack_into("<Q", blob, 0x98 + 24, 0x140000000)
        struct.pack_into("<I", blob, 0x98 + 56, 0x3000)
        struct.pack_into("<I", blob, 0x98 + 108, 16)
        struct.pack_into("<II", blob, 0x98 + 120, 0x2000, 40)
        struct.pack_into("<II", blob, 0x98 + 136, 0x1800, 24)
        blob[0x188:0x18D] = b".text"
        struct.pack_into("<IIIIII", blob, 0x188 + 8, 0x200, 0x1000, 0x200, 0x400, 0, 0)
        struct.pack_into("<I", blob, 0x188 + 36, 0x60000020)
        blob[0x1B0:0x1B5] = b".data"
        struct.pack_into("<IIIIII", blob, 0x1B0 + 8, 0x200, 0x2000, 0x200, 0x600, 0, 0)
        struct.pack_into("<I", blob, 0x1B0 + 36, 0xC0000040)
        blob[0x1D8:0x1DE] = b".pdata"
        struct.pack_into("<IIIIII", blob, 0x1D8 + 8, 0x100, 0x1800, 0x100, 0x300, 0, 0)
        struct.pack_into("<I", blob, 0x1D8 + 36, 0x40000040)
        blob[0x400:0x400 + len(code)] = code
        blob[0x500:0x501] = helper
        struct.pack_into("<IIIII", blob, 0x600, 0x2040, 0, 0, 0x2080, 0x2100)
        struct.pack_into("<Q", blob, 0x640, 0x2120)
        blob[0x680:0x68D] = b"KERNEL32.dll"
        blob[0x722:0x72F] = b"GetLastError"
        struct.pack_into("<III", blob, 0x300, 0x1000, 0x1000 + len(code), 0)
        struct.pack_into("<III", blob, 0x30C, 0x1100, 0x1101, 0)
        found = cfg_sandbox.discover_modeled_iat(bytes(blob))
        row = found["modeledCandidates"][0]
        self.assertEqual(row["reasons"], [])
        self.assertTrue(row["closure"]["proven"])
        self.assertEqual(row["closure"]["nodes"][0]["targets"][-1]["mnemonic"], "jmp")
        self.assertEqual(row["closure"]["nodes"][0]["targets"][-1]["target"], 0x1100)
        self.assertEqual(row["memory"], [])
        self.assertIn("xor", row["alu"])
        self.assertEqual(found["eligibleEntries"], [0x1000])
        self.assertNotIn("memory_access", found["reasonMembership"])
        verified = cfg_sandbox.verify_modeled_iat(bytes(blob), last_seed=0x55)
        self.assertTrue(verified["verifyExecuted"])
        self.assertFalse(verified["entryPointExecuted"])
        self.assertEqual(verified["verified"][0]["rax"], 0x55)
        self.assertEqual(verified["verified"][0]["rbx"], 0xA11CE)
        self.assertEqual(verified["verified"][0]["oracle"], "unicorn-canonical-stub")


class HighIatDiscoveryTests(unittest.TestCase):
    def test_high_rva_is_classified_and_a_clean_call_verifies(self):
        iat = 0x1750100
        code = bytes.fromhex("4883ec28")
        code += b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6))
        code += bytes.fromhex("4883c428c3")
        others = {
            0x1040: (0x1750108, "unmodeled"),
            0x1060: (0x1750110, "ordinal"),
            0x1080: (0x1750180, "unknown"),
            0x10A0: (0x1750FFC, "cross"),
        }
        blob = bytearray(0x900)
        blob[0:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3C, 0x80)
        blob[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", blob, 0x84, 0x8664, 3)
        struct.pack_into("<H", blob, 0x94, 0xF0)
        struct.pack_into("<H", blob, 0x98, 0x20B)
        struct.pack_into("<I", blob, 0x98 + 16, 0x1F00)
        struct.pack_into("<Q", blob, 0x98 + 24, 0x140000000)
        struct.pack_into("<I", blob, 0x98 + 56, 0x1761000)
        struct.pack_into("<I", blob, 0x98 + 108, 16)
        struct.pack_into("<II", blob, 0x98 + 120, 0x1750000, 40)
        struct.pack_into("<II", blob, 0x98 + 136, 0x3000, 60)
        blob[0x188:0x18D] = b".text"
        struct.pack_into("<IIIIII", blob, 0x188 + 8, 0x1000, 0x1000, 0x200, 0x200, 0, 0)
        struct.pack_into("<I", blob, 0x188 + 36, 0x60000020)
        blob[0x1B0:0x1B5] = b".data"
        struct.pack_into("<IIIIII", blob, 0x1B0 + 8, 0x1100, 0x1750000, 0x200, 0x400, 0, 0)
        struct.pack_into("<I", blob, 0x1B0 + 36, 0x40000040)
        blob[0x1D8:0x1DE] = b".pdata"
        struct.pack_into("<IIIIII", blob, 0x1D8 + 8, 0x100, 0x3000, 0x100, 0x600, 0, 0)
        struct.pack_into("<I", blob, 0x1D8 + 36, 0x40000040)
        blob[0x200:0x200 + len(code)] = code
        for addr, (target, _kind) in others.items():
            insn = b"\xff\x15" + struct.pack("<i", target - (addr + 6)) + b"\xc3"
            blob[0x200 + (addr - 0x1000):0x200 + (addr - 0x1000) + len(insn)] = insn
        struct.pack_into("<IIIII", blob, 0x400, 0x1750040, 0, 0, 0x1750080, 0x1750100)
        struct.pack_into("<Q", blob, 0x440, 0x1750120)
        struct.pack_into("<Q", blob, 0x448, 0x1750140)
        struct.pack_into("<Q", blob, 0x450, 0x8000000000000007)
        blob[0x480:0x48D] = b"KERNEL32.dll"
        blob[0x522:0x522 + 13] = b"GetLastError"
        blob[0x542:0x542 + 12] = b"ExitProcess"
        pdata = [(0x1000, 0x1000 + len(code))]
        pdata += [(addr, addr + 7) for addr in others]
        for index, (begin, end) in enumerate(pdata):
            struct.pack_into("<III", blob, 0x600 + index * 12, begin, end, 0)
        found = cfg_sandbox.discover_modeled_iat(bytes(blob))
        self.assertFalse(found["executed"])
        self.assertEqual(found["eligibleEntries"], [0x1000])
        self.assertEqual(found["obstacles"].get("iat_unmodeled"), 1)
        self.assertEqual(found["obstacles"].get("iat_ordinal"), 1)
        self.assertEqual(found["obstacles"].get("unknown_iat"), 1)
        self.assertEqual(found["obstacles"].get("iat_cross_page"), 1)
        self.assertNotIn("iat_oob", found["obstacles"])
        verified = cfg_sandbox.verify_modeled_iat(bytes(blob), last_seed=0x55)
        self.assertTrue(verified["verifyExecuted"])
        self.assertFalse(verified["entryPointExecuted"])
        self.assertEqual(verified["verified"][0]["rax"], 0x55)
        self.assertEqual(verified["verified"][0]["oracle"], "unicorn-canonical-stub")
        self.assertEqual(verified["verified"][0]["rbx"], 0xA11CE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
