#!/usr/bin/env python3
"""Read-only PE32+ / AMD64 header inspector.

ImageBase is the 8-byte field at optional-header offset 24. The PE32 ImageBase
at offset 28 and the PE32 import directory at offset 104 are not used. The
entry point is reported as an RVA and is not disassembled. A .bind section is
a name and characteristics only.
"""
import argparse
import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024
BIND_NOTE = (
    "A .bind section is only a section name and characteristics. "
    "Its presence or absence does not show whether any bytes are encrypted, packed, or decrypted."
)


class PeFormatError(Exception):
    pass


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _need(data, off, size):
    if off < 0 or size < 0 or off + size > len(data):
        raise PeFormatError("truncated PE at offset %#x" % off)
    return off


def u16(data, off):
    _need(data, off, 2)
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    _need(data, off, 4)
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    _need(data, off, 8)
    return struct.unpack_from("<Q", data, off)[0]


def _sections(data, off, count):
    if count > 96:
        raise PeFormatError("too many sections")
    out = []
    for i in range(count):
        o = _need(data, off + i * 40, 40)
        raw_name = data[o:o + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PeFormatError("section name is not ASCII") from exc
        chars = u32(data, o + 36)
        out.append({
            "name": name,
            "virtualSize": u32(data, o + 8),
            "virtualAddress": u32(data, o + 12),
            "sizeOfRawData": u32(data, o + 16),
            "pointerToRawData": u32(data, o + 20),
            "characteristics": chars,
            "characteristicsHex": "0x%08X" % chars,
            "executable": bool(chars & 0x20000000),
            "writable": bool(chars & 0x80000000),
        })
    return out


def _rva_to_off(sections, rva, size):
    for sec in sections:
        span = max(sec["virtualSize"], sec["sizeOfRawData"])
        va = sec["virtualAddress"]
        if va <= rva < va + span:
            delta = rva - va
            if delta + size > sec["sizeOfRawData"]:
                raise PeFormatError("RVA %#x is outside the section's raw bytes" % rva)
            return sec["pointerToRawData"] + delta
    raise PeFormatError("RVA %#x is not in a section" % rva)


def _cstr(data, sections, rva):
    chars = []
    for i in range(128):
        off = _rva_to_off(sections, rva + i, 1)
        byte = data[_need(data, off, 1)]
        if byte == 0:
            try:
                name = bytes(chars).decode("ascii")
            except UnicodeDecodeError as exc:
                raise PeFormatError("import DLL name is not ASCII") from exc
            allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
            if not name or any(ch not in allowed for ch in name):
                raise PeFormatError("import DLL name is not a plain file name")
            return name
        chars.append(byte)
    raise PeFormatError("import DLL name is not terminated")


def _imports(data, sections, directories):
    if len(directories) < 2 or directories[1][0] == 0:
        return []
    rva, size = directories[1]
    if size > 20 * 64:
        raise PeFormatError("import directory is too large")
    found = []
    for index in range(64):
        desc = rva + index * 20
        off = _rva_to_off(sections, desc, 20)
        oft, _tds, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0 and first_thunk == 0:
            break
        dll = _cstr(data, sections, name_rva)
        thunk = oft or first_thunk
        count = 0
        while count < 4096:
            toff = _rva_to_off(sections, thunk, 8)
            value = u64(data, toff)
            if value == 0:
                break
            count += 1
            thunk += 8
        found.append({"dll": dll, "count": count})
    return found


def inspect_bytes(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PeFormatError("not a PE file (missing MZ)")
    e_lfanew = u32(data, 0x3C)
    if e_lfanew < 0x40 or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PeFormatError("missing PE signature")
    fh = e_lfanew + 4
    machine = u16(data, fh)
    nsec = u16(data, fh + 2)
    stamp = u32(data, fh + 4)
    optsize = u16(data, fh + 16)
    characteristics = u16(data, fh + 18)
    if machine != 0x8664:
        raise PeFormatError(
            "refusing machine 0x%04x; only IMAGE_FILE_MACHINE_AMD64 (0x8664) is accepted" % machine)
    if optsize < 112:
        raise PeFormatError("optional header is too small for PE32+")
    opt = fh + 20
    _need(data, opt, optsize)
    magic = u16(data, opt)
    if magic != 0x20B:
        raise PeFormatError(
            "refusing magic 0x%X; this inspector reads only PE32+ (magic 0x20B)" % magic)
    # PE32+ layout only. Do not read a 32-bit ImageBase from offset 28.
    image_base = u64(data, opt + 24)
    entry = u32(data, opt + 16)
    nrva = u32(data, opt + 108)
    if nrva > 16:
        raise PeFormatError("refusing NumberOfRvaAndSizes %d" % nrva)
    if optsize < 112 + nrva * 8:
        raise PeFormatError("data directories extend past SizeOfOptionalHeader")
    directories = [(u32(data, opt + 112 + i * 8), u32(data, opt + 112 + i * 8 + 4)) for i in range(nrva)]
    sections = _sections(data, opt + optsize, nsec)
    imports = _imports(data, sections, directories)
    exception = directories[3] if len(directories) > 3 else (0, 0)
    utc = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "machine": "IMAGE_FILE_MACHINE_AMD64",
        "machineValue": machine,
        "magic": "PE32+",
        "magicValue": magic,
        "imageBase": image_base,
        "sizeOfImage": u32(data, opt + 56),
        "sizeOfHeaders": u32(data, opt + 60),
        "sectionAlignment": u32(data, opt + 32),
        "fileAlignment": u32(data, opt + 36),
        "addressOfEntryPoint": entry,
        "entryPointDisassembled": False,
        "timeDateStamp": stamp,
        "timeDateStampUtc": utc,
        "numberOfSections": nsec,
        "characteristics": characteristics,
        "characteristicsHex": "0x%04X" % characteristics,
        "subsystem": u16(data, opt + 68),
        "dllCharacteristics": u16(data, opt + 70),
        "dllCharacteristicsHex": "0x%04X" % u16(data, opt + 70),
        "sections": sections,
        "imports": imports,
        "exceptionDirectory": {
            "present": bool(exception[0] or exception[1]),
            "virtualAddress": exception[0],
            "size": exception[1],
        },
        "bindSection": {
            "present": any(sec["name"] == ".bind" for sec in sections),
            "note": BIND_NOTE,
        },
        "pdataSection": {"present": any(sec["name"] == ".pdata" for sec in sections)},
        "notes": [
            "PE32 optional-header layout is not used.",
            "Entry point bytes are not disassembled.",
            BIND_NOTE,
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only AMD64 PE32+ inspector. Does not disassemble.")
    parser.add_argument("path")
    parser.add_argument("--json", action="store_true", help="print the report as JSON (always on)")
    parser.add_argument("--expect-sha256", help="require this SHA-256 of the whole file")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if not path.is_file():
        print("not a file: %s" % path, file=sys.stderr)
        return 1
    if path.stat().st_size > MAX_FILE:
        print("file exceeds the 64 MiB inspection cap", file=sys.stderr)
        return 1
    data = path.read_bytes()
    digest = sha256_hex(data)
    if args.expect_sha256 and digest.lower() != args.expect_sha256.lower():
        print("sha256 mismatch: got %s" % digest, file=sys.stderr)
        return 3
    try:
        info = inspect_bytes(data)
    except PeFormatError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    info["sha256"] = digest
    info["size"] = len(data)
    json.dump(info, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
