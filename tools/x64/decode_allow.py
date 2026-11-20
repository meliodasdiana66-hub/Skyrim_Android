"""Pure-Python allowlist decoder for the x64 prototype.

Stdlib only, so a Windows dry-run does not need capstone. It is conservative:
a byte string it accepts must also be accepted by lift64, which is checked by
tests. Unknown bytes raise Reject. A leaf must end in a single unprefixed
one-byte ret, and that ret is reported but not treated as a memory access.
"""


class Reject(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _need(code, index, size):
    if index < 0 or size < 0 or index + size > len(code):
        raise Reject("undecodable")
    return index


def _s32(raw):
    value = int.from_bytes(raw, "little")
    if value & 0x80000000:
        value -= 0x100000000
    return value


def decode_stream(code, base):
    """Decode a straight-line allowlisted snippet. Does not require a final ret."""
    if not code:
        raise Reject("undecodable")
    index = 0
    out = []
    while index < len(code):
        insn, size = _one(code, index, base + index)
        out.append(insn)
        index += size
    return out


def decode_leaf(code, base):
    """A pdata leaf: at least one allowlisted instruction and a final one-byte ret."""
    insns = decode_stream(code, base)
    if insns[-1]["mnemonic"] != "ret":
        raise Reject("no_ret")
    if any(insn["mnemonic"] == "ret" for insn in insns[:-1]):
        raise Reject("ret_not_final")
    if len(insns) == 1:
        raise Reject("empty_body")
    return insns


def _one(code, start, addr):
    index = start
    rex = None
    opsize16 = False
    for _ in range(4):
        _need(code, index, 1)
        byte = code[index]
        if byte == 0x66:
            opsize16 = True
            index += 1
            continue
        if byte == 0x67:
            raise Reject("address_size")
        if byte == 0xF0:
            raise Reject("lock")
        if byte in (0xF2, 0xF3):
            raise Reject("rep")
        if byte in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):
            raise Reject("segment")
        if 0x40 <= byte <= 0x4F:
            if rex is not None:
                raise Reject("undecodable")
            rex = byte
            index += 1
            continue
        break
    _need(code, index, 1)
    op = code[index]
    rex_w = bool(rex is not None and rex & 8)
    rex_r = bool(rex is not None and rex & 4)
    rex_b = bool(rex is not None and rex & 1)
    rex_x = bool(rex is not None and rex & 2)
    if rex_w and opsize16:
        raise Reject("unsupported")

    def width():
        if rex_w:
            return 64
        if opsize16:
            return 16
        return 32

    def finish(mnemonic, cursor, reads, writes, rip=None):
        size = cursor - start
        return {
            "mnemonic": mnemonic,
            "address": addr,
            "size": size,
            "reads": reads,
            "writes": writes,
            "rip": rip,
        }, size

    if op == 0xC3:
        if rex is not None or opsize16 or index != start:
            raise Reject("ret_form")
        return finish("ret", index + 1, [], [])
    if op == 0xC2:
        raise Reject("ret_form")
    if op == 0xE8:
        raise Reject("call")
    if op in (0xE9, 0xEB):
        raise Reject("jump")
    if 0x70 <= op <= 0x7F:
        raise Reject("jcc")
    if 0x50 <= op <= 0x57:
        raise Reject("push")
    if 0x58 <= op <= 0x5F:
        raise Reject("pop")
    if op == 0x90 and rex is None and not opsize16:
        return finish("nop", index + 1, [], [])
    if op == 0x0F:
        _need(code, index + 1, 1)
        second = code[index + 1]
        if 0x80 <= second <= 0x8F:
            raise Reject("jcc")
        if second not in (0xB6, 0xB7) or opsize16:
            raise Reject("unsupported")
        reg, kind, cursor = _modrm(code, index + 2, addr, start, rex_r, rex_b, rex_x)
        if kind[0] != "reg":
            raise Reject("memory_form")
        src_bits = 8 if second == 0xB6 else 16
        _gpr(kind[1], src_bits, rex is not None)
        dest_bits = 64 if rex_w else 32
        _gpr(reg, dest_bits, rex is not None)
        return finish("movzx", cursor, [(kind[1], src_bits)], [(reg, dest_bits)])

    if 0xB0 <= op <= 0xB7:
        reg = (op - 0xB0) + (8 if rex_b else 0)
        _gpr(reg, 8, rex is not None)
        _need(code, index + 1, 1)
        return finish("mov", index + 2, [], [(reg, 8)])
    if 0xB8 <= op <= 0xBF:
        bits = width()
        reg = (op - 0xB8) + (8 if rex_b else 0)
        _gpr(reg, bits, rex is not None)
        imm = 8 if bits == 64 else (2 if bits == 16 else 4)
        _need(code, index + 1, imm)
        return finish("mov", index + 1 + imm, [], [(reg, bits)])
    if op == 0x05:
        bits = width()
        _need(code, index + 1, 4)
        return finish("add", index + 5, [(0, bits)], [(0, bits)])

    if op in (0x80, 0x81, 0x83):
        reg, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        if kind[0] != "reg" or reg != 0:
            # Only add-immediate to a register. Other group ops and memory forms
            # are outside the lifter.
            raise Reject("unsupported" if kind[0] == "reg" else "memory_form")
        bits = 8 if op == 0x80 else width()
        if op == 0x83 and bits == 8:
            raise Reject("unsupported")
        _gpr(kind[1], bits, rex is not None)
        imm = 1 if op in (0x80, 0x83) else 4
        _need(code, cursor, imm)
        return finish("add", cursor + imm, [(kind[1], bits)], [(kind[1], bits)])

    alu = {
        0x01: ("add", "rm"), 0x03: ("add", "reg"),
        0x29: ("sub", "rm"), 0x2B: ("sub", "reg"),
        0x21: ("and", "rm"), 0x23: ("and", "reg"),
        0x09: ("or", "rm"), 0x0B: ("or", "reg"),
        0x31: ("xor", "rm"), 0x33: ("xor", "reg"),
        0x39: ("cmp", "rm"), 0x3B: ("cmp", "reg"),
        0x85: ("test", "rm"),
    }
    mov = {
        0x88: ("mov", "rm", 8), 0x8A: ("mov", "reg", 8),
        0x89: ("mov", "rm", 0), 0x8B: ("mov", "reg", 0),
    }
    if op in alu:
        mnemonic, shape = alu[op]
        reg, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        bits = width()
        if kind[0] != "reg":
            raise Reject("memory_form")
        _gpr(reg, bits, rex is not None)
        _gpr(kind[1], bits, rex is not None)
        write = mnemonic not in ("cmp", "test")
        if shape == "rm":
            reads = [(kind[1], bits), (reg, bits)]
            writes = [(kind[1], bits)] if write else []
        else:
            reads = [(reg, bits), (kind[1], bits)]
            writes = [(reg, bits)] if write else []
        return finish(mnemonic, cursor, reads, writes)
    if op in mov:
        mnemonic, shape, bits = mov[op]
        if bits == 0:
            bits = width()
        reg, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        _gpr(reg, bits, rex is not None)
        rip = None
        if kind[0] == "rip":
            target, disp_end = kind[1], cursor
            rip = (target, bits // 8)
            if shape == "rm":
                return finish(mnemonic, disp_end, [(reg, bits)], [], rip)
            return finish(mnemonic, disp_end, [], [(reg, bits)], rip)
        _gpr(kind[1], bits, rex is not None)
        if shape == "rm":
            return finish(mnemonic, cursor, [(reg, bits)], [(kind[1], bits)])
        return finish(mnemonic, cursor, [(kind[1], bits)], [(reg, bits)])
    raise Reject("unsupported")


def _gpr(index, bits, has_rex):
    if bits == 8 and not has_rex and 4 <= (index & 7) <= 7 and index < 8:
        raise Reject("high_byte")
    if not 0 <= index < 16:
        raise Reject("unsupported")


def _modrm(code, index, addr, start, rex_r, rex_b, rex_x):
    _need(code, index, 1)
    byte = code[index]
    mod = byte >> 6
    reg = ((byte >> 3) & 7) + (8 if rex_r else 0)
    rm_low = byte & 7
    index += 1
    if mod == 3:
        rm = rm_low + (8 if rex_b else 0)
        return reg, ("reg", rm), index
    if rex_x or rm_low == 4:
        raise Reject("memory_form")
    if mod == 0 and rm_low == 5:
        _need(code, index, 4)
        disp = _s32(code[index:index + 4])
        index += 4
        next_ip = addr + (index - start)
        return reg, ("rip", next_ip + disp), index
    raise Reject("memory_form")
