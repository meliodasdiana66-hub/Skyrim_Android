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
        self.assertEqual(result["oracle"], "unicorn-stub-at-token-address")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
