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


def decode_stream(code, base, control=False):
    """Decode a straight-line allowlisted snippet. Does not require a final ret.

    control=True is only for the explicit CFG sandbox. The leaf decoder keeps it false,
    so call and jcc stay rejected there.
    """
    if not code:
        raise Reject("undecodable")
    index = 0
    out = []
    while index < len(code):
        insn, size = _one(code, index, base + index, control=control)
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


JCC = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg")


def _one(code, start, addr, control=False):
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

    def finish(mnemonic, cursor, reads, writes, rip=None, mem=None, stack=None, imm=None,
               lea_target=None, lea_disp=None, xmm=None, branch=None, iat=None):
        size = cursor - start
        insn = {
            "mnemonic": mnemonic,
            "address": addr,
            "size": size,
            "reads": reads,
            "writes": writes,
            "rip": rip,
        }
        if mem is not None:
            insn["mem"] = mem
        if stack is not None:
            insn["stack"] = stack
        if imm is not None:
            insn["imm"] = imm
        if lea_target is not None:
            insn["leaTarget"] = lea_target
        if branch is not None:
            insn["target"] = branch
        if lea_disp is not None:
            insn["leaDisp"] = lea_disp
        if iat is not None:
            insn["iat"] = iat
        if xmm is not None:
            insn["xmm"] = xmm
        return insn, size

    if op == 0xC3:
        if rex is not None or opsize16 or index != start:
            raise Reject("ret_form")
        return finish("ret", index + 1, [], [])
    if op == 0xC2:
        raise Reject("ret_form")
    if op == 0xE8:
        if not control:
            raise Reject("call")
        _need(code, index + 1, 4)
        rel = _s32(code[index + 1:index + 5])
        cursor = index + 5
        return finish("call", cursor, [], [], branch=addr + (cursor - start) + rel)
    if op == 0xE9:
        if not control:
            raise Reject("jump")
        _need(code, index + 1, 4)
        rel = _s32(code[index + 1:index + 5])
        cursor = index + 5
        return finish("jmp", cursor, [], [], branch=addr + (cursor - start) + rel)
    if op == 0xEB:
        if not control:
            raise Reject("jump")
        _need(code, index + 1, 1)
        rel = _sext(code[index + 1], 8)
        cursor = index + 2
        return finish("jmp", cursor, [], [], branch=addr + (cursor - start) + rel)
    if 0x70 <= op <= 0x7F:
        if not control:
            raise Reject("jcc")
        _need(code, index + 1, 1)
        rel = _sext(code[index + 1], 8)
        cursor = index + 2
        return finish(JCC[op - 0x70], cursor, [], [], branch=addr + (cursor - start) + rel)
    if op == 0xFF:
        if not control:
            raise Reject("unsupported")
        ext, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        if ext == 2 and kind[0] == "rip":
            return finish("call_rip", cursor, [], [], iat=kind[1])
        raise Reject("indirect_call" if ext == 2 else "indirect_branch")
    if 0x50 <= op <= 0x5F:
        if opsize16:
            raise Reject("push_width")
        if rex_x or rex_r:
            raise Reject("unsupported")
        reg = (op & 7) + (8 if rex_b else 0)
        if reg == 4:
            raise Reject("push_rsp" if op <= 0x57 else "pop_rsp")
        _gpr(reg, 64, rex is not None)
        if op <= 0x57:
            return finish("push", index + 1, [(reg, 64)], [(4, 64)], stack=("push", 8))
        return finish("pop", index + 1, [(4, 64)], [(reg, 64), (4, 64)], stack=("pop", 8))
    if op in (0x6A, 0x68):
        if rex is not None or opsize16:
            raise Reject("unsupported")
        if op == 0x6A:
            _need(code, index + 1, 1)
            return finish("push", index + 2, [], [(4, 64)], stack=("push", 8), imm=_sext(code[index + 1], 8))
        _need(code, index + 1, 4)
        raw = int.from_bytes(code[index + 1:index + 5], "little")
        return finish("push", index + 5, [], [(4, 64)], stack=("push", 8), imm=_sext(raw, 32))
    if op == 0x90 and rex is None and not opsize16:
        return finish("nop", index + 1, [], [])
    if op == 0x0F:
        _need(code, index + 1, 1)
        second = code[index + 1]
        if 0x80 <= second <= 0x8F:
            if not control:
                raise Reject("jcc")
            _need(code, index + 2, 4)
            rel = _s32(code[index + 2:index + 6])
            cursor = index + 6
            return finish(JCC[second - 0x80], cursor, [], [], branch=addr + (cursor - start) + rel)
        if second in (0x28, 0x29):
            xreg, kind, cursor = _modrm(code, index + 2, addr, start, rex_r, rex_b, rex_x)
            if not 0 <= xreg < 16:
                raise Reject("unsupported")
            if kind[0] == "reg":
                if not 0 <= kind[1] < 16:
                    raise Reject("unsupported")
                if second == 0x28:
                    return finish("movaps", cursor, [], [], xmm=(xreg, kind[1]))
                return finish("movaps", cursor, [], [], xmm=(kind[1], xreg))
            if kind[0] not in ("rsp", "base"):
                raise Reject("memory_form")
            slot = _slot(kind, 16, "load" if second == 0x28 else "store")
            return finish("movaps", cursor, slot[0], [], mem=slot[1], xmm=(xreg, None))
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

    if op == 0xC7:
        ext, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        if ext != 0 or kind[0] not in ("rsp", "base"):
            raise Reject("unsupported" if kind[0] == "reg" else "memory_form")
        if opsize16:
            raise Reject("unsupported")
        _need(code, cursor, 4)
        raw = int.from_bytes(code[cursor:cursor + 4], "little")
        if rex_w:
            size, imm = 8, _sext(raw, 32)
        else:
            size, imm = 4, raw & 0xFFFFFFFF
        reads, slot = _slot(kind, size, "store")
        return finish("mov", cursor + 4, reads, [], mem=slot, imm=imm)
    if op == 0x2D:
        bits = width()
        _need(code, index + 1, 4)
        addend = _sext(int.from_bytes(code[index + 1:index + 5], "little"), 32)
        return finish("sub", index + 5, [(0, bits)], [(0, bits)], imm=addend)
    if op == 0x8D:
        if opsize16:
            raise Reject("lea_width")
        reg, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        bits = 64 if rex_w else 32
        if kind[0] == "reg" or reg == 4:
            raise Reject("lea_form")
        _gpr(reg, bits, rex is not None)
        if kind[0] == "rip":
            return finish("lea", cursor, [], [(reg, bits)], lea_target=kind[1])
        if kind[0] == "rsp":
            return finish("lea", cursor, [(4, 64)], [(reg, bits)], lea_disp=kind[1])
        if kind[0] == "base":
            return finish("lea", cursor, [(kind[1], 64)], [(reg, bits)], lea_disp=kind[2])
        raise Reject("lea_form")
    if op in (0x80, 0x81, 0x83):
        ext, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        mnemonic = {0: "add", 5: "sub"}.get(ext)
        if kind[0] != "reg" or mnemonic is None:
            raise Reject("unsupported" if kind[0] == "reg" else "memory_form")
        bits = 8 if op == 0x80 else width()
        if op == 0x83 and bits == 8:
            raise Reject("unsupported")
        _gpr(kind[1], bits, rex is not None)
        imm_len = 1 if op in (0x80, 0x83) else 4
        _need(code, cursor, imm_len)
        if imm_len == 1:
            addend = _sext(code[cursor], 8)
        else:
            addend = _sext(int.from_bytes(code[cursor:cursor + 4], "little"), 32)
        return finish(mnemonic, cursor + imm_len, [(kind[1], bits)], [(kind[1], bits)], imm=addend)

    if op == 0xA8:
        _need(code, index + 1, 1)
        return finish("test", index + 2, [(0, 8)], [], imm=code[index + 1])
    if op == 0xA9:
        bits = width()
        _need(code, index + 1, 4)
        raw = int.from_bytes(code[index + 1:index + 5], "little")
        addend = _sext(raw, 32) if bits == 64 else raw & 0xFFFFFFFF
        return finish("test", index + 5, [(0, bits)], [], imm=addend)
    if op == 0xF7:
        ext, kind, cursor = _modrm(code, index + 1, addr, start, rex_r, rex_b, rex_x)
        if ext != 0 or kind[0] != "reg":
            raise Reject("unsupported" if kind[0] == "reg" else "memory_form")
        bits = width()
        _gpr(kind[1], bits, rex is not None)
        _need(code, cursor, 4)
        raw = int.from_bytes(code[cursor:cursor + 4], "little")
        addend = _sext(raw, 32) if bits == 64 else raw & 0xFFFFFFFF
        return finish("test", cursor + 4, [(kind[1], bits)], [], imm=addend)
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
        if kind[0] in ("rsp", "base"):
            if bits not in (8, 16, 32, 64):
                raise Reject("memory_form")
            access = "store" if shape == "rm" else "load"
            reads, slot = _slot(kind, bits // 8, access)
            if shape == "rm":
                return finish(mnemonic, cursor, reads + [(reg, bits)], [], mem=slot)
            return finish(mnemonic, cursor, reads, [(reg, bits)], mem=slot)
        _gpr(kind[1], bits, rex is not None)
        if shape == "rm":
            return finish(mnemonic, cursor, [(reg, bits)], [(kind[1], bits)])
        return finish(mnemonic, cursor, [(kind[1], bits)], [(reg, bits)])
    raise Reject("unsupported")


def _slot(kind, size, access):
    if kind[0] == "rsp":
        return [(4, 64)], ("rsp", kind[1], size, access)
    if kind[0] == "base":
        return [(kind[1], 64)], ("base", kind[1], kind[2], size, access)
    raise Reject("memory_form")


def _sext(value, bits):
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


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
    if rm_low == 4:
        _need(code, index, 1)
        sib = code[index]
        index += 1
        if rex_x or ((sib >> 3) & 7) != 4:
            raise Reject("memory_form")
        base_low = sib & 7
        if mod == 0 and base_low == 5:
            raise Reject("memory_form")
        if mod == 1:
            _need(code, index, 1)
            disp = _sext(code[index], 8)
            index += 1
        elif mod == 2:
            _need(code, index, 4)
            disp = _s32(code[index:index + 4])
            index += 4
        elif mod == 0:
            disp = 0
        else:
            raise Reject("memory_form")
        base = base_low + (8 if rex_b else 0)
        if base == 4:
            return reg, ("rsp", disp), index
        return reg, ("base", base, disp), index
    if rex_x:
        raise Reject("memory_form")
    if mod == 0 and rm_low == 5:
        _need(code, index, 4)
        disp = _s32(code[index:index + 4])
        index += 4
        next_ip = addr + (index - start)
        return reg, ("rip", next_ip + disp), index
    if mod == 0:
        disp = 0
    elif mod == 1:
        _need(code, index, 1)
        disp = _sext(code[index], 8)
        index += 1
    elif mod == 2:
        _need(code, index, 4)
        disp = _s32(code[index:index + 4])
        index += 4
    else:
        raise Reject("memory_form")
    return reg, ("base", rm_low + (8 if rex_b else 0), disp), index
