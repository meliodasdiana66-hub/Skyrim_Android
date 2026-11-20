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
        "mapRefusal": "SizeOfImage exceeds the 1 MiB synthetic map cap" if info["sizeOfImage"] > MAX_MAP else None,
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
        report = inventory(data)
    except inspect_pe32plus.PeFormatError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report["sha256"] = digest
    report["size"] = len(data)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
