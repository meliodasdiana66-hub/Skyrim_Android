#!/usr/bin/env python3
"""Bounded PE32+ inventory and synthetic mapper. Not a game loader.

inventory() records headers, sections, and import slots. It does not bind
imports or call the entry point. map_synthetic() copies a small image into a
buffer and can apply DIR64 relocations. Images larger than MAX_MAP, including
SkyrimSE.exe, are refused rather than mapped.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

import inspect_pe32plus

MAX_MAP = 1 << 20
DIR64 = 10


class LoadError(Exception):
    pass


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _imports(data, sections, image_info):
    rows = []
    for row in image_info["imports"]:
        rows.append({
            "dll": row["dll"],
            "slots": row["count"],
            "binding": "not_implemented",
        })
    return rows


def inventory(data):
    """Header and import inventory. Does not map the image and does not call anything."""
    info = inspect_pe32plus.inspect_bytes(data)
    graphics = [row["dll"] for row in info["imports"]
                if row["dll"].lower() in ("d3d11.dll", "dxgi.dll", "d3dx9_42.dll")]
    return {
        "kind": "pe32plus-inventory",
        "mapped": False,
        "entryCalled": False,
        "imageBase": info["imageBase"],
        "sizeOfImage": info["sizeOfImage"],
        "addressOfEntryPoint": info["addressOfEntryPoint"],
        "sections": [{
            "name": sec["name"],
            "virtualAddress": sec["virtualAddress"],
            "virtualSize": sec["virtualSize"],
            "sizeOfRawData": sec["sizeOfRawData"],
            "executable": sec["executable"],
        } for sec in info["sections"]],
        "imports": _imports(data, info["sections"], info),
        "baseRelocation": info["baseRelocation"],
        "implemented": [
            "amd64_pe32plus_header",
            "section_table",
            "import_directory_walk",
        ],
        "inventoried_not_implemented": [
            "import_binding",
            "entry_point_call",
            "tls_callbacks",
            "exception_dispatch",
            "graphics",
        ],
        "graphicsImportsNotImplemented": graphics,
        "mapRefused": info["sizeOfImage"] > MAX_MAP,
        "mapRefusal": (
            "dense bytearray copy refused above 1 MiB; logical intervals do not allocate SizeOfImage"
            if info["sizeOfImage"] > MAX_MAP else None),
        "guestAllocation": None,
        "logicalIntervalCount": len(logical_intervals(info)),
    }


def _perms(chars):
    return {
        "read": bool(chars & 0x40000000),
        "write": bool(chars & 0x80000000),
        "execute": bool(chars & 0x20000000),
    }


def logical_intervals(info):
    """Describe the image as RVA intervals. Does not allocate SizeOfImage or copy bytes."""
    size = info["sizeOfImage"]
    if size <= 0 or size > 0x7FFFFFFF:
        raise LoadError("SizeOfImage is not a usable logical span")
    headers = min(info["sizeOfHeaders"], size)
    intervals = []
    cursor = 0
    if headers:
        intervals.append({
            "start": 0, "end": headers, "state": "file-backed", "role": "headers",
            "permissions": {"read": True, "write": False, "execute": False},
            "materialized": False,
        })
        cursor = headers
    for sec in sorted(info["sections"], key=lambda item: item["virtualAddress"]):
        va = sec["virtualAddress"]
        if va >= size:
            continue
        vend = min(size, va + sec["virtualSize"])
        if cursor < va:
            intervals.append({"start": cursor, "end": va, "state": "unmapped", "role": "gap", "materialized": False})
        backed = min(sec["sizeOfRawData"], sec["virtualSize"], vend - va)
        perms = _perms(sec["characteristics"])
        if backed:
            intervals.append({
                "start": va, "end": va + backed, "state": "file-backed", "role": "section",
                "section": sec["name"], "fileOffset": sec["pointerToRawData"],
                "permissions": perms, "materialized": False,
            })
        if va + backed < vend:
            intervals.append({
                "start": va + backed, "end": vend, "state": "zero-fill", "role": "section",
                "section": sec["name"], "permissions": perms, "materialized": False,
            })
        cursor = max(cursor, vend)
    if cursor < size:
        intervals.append({"start": cursor, "end": size, "state": "unmapped", "role": "tail", "materialized": False})
    covered = 0
    previous = 0
    for row in intervals:
        if row["start"] != previous or row["end"] < row["start"]:
            raise LoadError("logical intervals do not tile the image")
        covered += row["end"] - row["start"]
        previous = row["end"]
    if covered != size or previous != size:
        raise LoadError("logical intervals do not cover SizeOfImage")
    return intervals


def logical_map(data):
    """Sparse description of a PE32+ image. No guest allocation and no entry call."""
    info = inspect_pe32plus.inspect_bytes(data)
    tls = info.get("tlsDirectory") or {"present": False}
    return {
        "kind": "logical-map",
        "guestAllocation": None,
        "addressSpace": "rva-intervals",
        "sizeOfImage": info["sizeOfImage"],
        "entryCalled": False,
        "importsBound": False,
        "relocationsApplied": False,
        "tlsCallbacksRun": False,
        "unwindDispatched": False,
        "originalBytesCopied": False,
        "exceptionDirectoryPresent": info["exceptionDirectory"]["present"],
        "tlsPresent": bool(tls.get("present")),
        "intervals": logical_intervals(info),
    }


def map_synthetic(data, relocate_to=None):
    """Copy a small synthetic image and optionally apply DIR64 relocations.

    The entry point is not called. Unknown relocation types fail closed.
    """
    info = inspect_pe32plus.inspect_bytes(data)
    size = info["sizeOfImage"]
    if size <= 0 or size > MAX_MAP:
        raise LoadError("refusing to map SizeOfImage %#x; cap is %#x" % (size, MAX_MAP))
    buf = bytearray(size)
    for sec in info["sections"]:
        va = sec["virtualAddress"]
        raw_n = sec["sizeOfRawData"]
        virt = sec["virtualSize"]
        if va > size:
            raise LoadError("section RVA is outside SizeOfImage")
        n = min(raw_n, virt, size - va)
        if n:
            off = inspect_pe32plus.file_offset_for_rva(info["sections"], va, n)
            buf[va:va + n] = data[off:off + n]
    applied = 0
    reloc = info["baseRelocation"]
    if relocate_to is not None:
        if relocate_to < 0 or relocate_to > 0xFFFFFFFFFFFFFFFF:
            raise LoadError("bad relocation base")
        delta = (relocate_to - info["imageBase"]) & 0xFFFFFFFFFFFFFFFF
        if reloc["present"] and reloc["size"]:
            off = inspect_pe32plus.file_offset_for_rva(info["sections"], reloc["virtualAddress"], reloc["size"])
            blob = data[off:off + reloc["size"]]
            cursor = 0
            while cursor + 8 <= len(blob):
                block_va = _u32(blob, cursor)
                block_size = _u32(blob, cursor + 4)
                if block_size < 8 or cursor + block_size > len(blob):
                    raise LoadError("truncated relocation block")
                for at in range(cursor + 8, cursor + block_size, 2):
                    entry = _u16(blob, at)
                    typ = entry >> 12
                    target = block_va + (entry & 0xFFF)
                    if typ == 0:
                        continue
                    if typ != DIR64:
                        raise LoadError("unsupported relocation type %d" % typ)
                    if target + 8 > size:
                        raise LoadError("relocation outside the image")
                    value = (_u64(buf, target) + delta) & 0xFFFFFFFFFFFFFFFF
                    struct.pack_into("<Q", buf, target, value)
                    applied += 1
                cursor += block_size
    return {
        "mapped": True,
        "entryCalled": False,
        "imageBase": info["imageBase"] if relocate_to is None else relocate_to,
        "preferredBase": info["imageBase"],
        "sizeOfImage": size,
        "addressOfEntryPoint": info["addressOfEntryPoint"],
        "relocationsApplied": applied,
        "importsBound": 0,
        "image": bytes(buf),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="PE32+ inventory. Does not launch a game or map large images.")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--expect-sha256")
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--logical-map", action="store_true",
                        help="print RVA intervals only; does not copy section bytes or call the entry")
    args = parser.parse_args(argv)
    path = Path(args.exe)
    if not path.is_file():
        print("not a file", file=sys.stderr)
        return 1
    if path.stat().st_size > inspect_pe32plus.MAX_FILE:
        print("file exceeds the 64 MiB cap", file=sys.stderr)
        return 1
    data = path.read_bytes()
    digest = inspect_pe32plus.sha256_hex(data)
    if args.expect_sha256 and digest.lower() != args.expect_sha256.lower():
        print("sha256 mismatch", file=sys.stderr)
        return 3
    try:
        report = logical_map(data) if args.logical_map else inventory(data)
    except (inspect_pe32plus.PeFormatError, LoadError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report["sha256"] = digest
    report["size"] = len(data)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
