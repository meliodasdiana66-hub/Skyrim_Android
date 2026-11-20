"""Allowlisted x86-64 to C lifter for synthetic fixtures.

Refuses PE images, LOCK, REP, segment and address-size overrides, and any
instruction outside the allowlist. This is not tools/lift.py and it does not
accept a PE32 or PE32+ file.
"""
import capstone
from capstone import x86

MAX_CODE = 4096

ALLOW = frozenset({
    "nop", "mov", "movabs", "movzx", "add", "sub", "cmp", "and", "or", "xor", "test",
    "push", "pop", "lea", "movaps",
})

_WIDTHS = (
    (64, ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]),
    (32, ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]),
    (16, ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
          "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]),
    (8, ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
         "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]),
)
REG_INFO = {name: (index, bits) for bits, names in _WIDTHS for index, name in enumerate(names)}
HIGH_BYTE = {"ah", "ch", "dh", "bh"}


class Unsupported(Exception):
    """The bytes are outside this prototype. No C is returned."""


def _decode(code, base):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    off = 0
    out = []
    while off < len(code):
        decoded = list(md.disasm(code[off:off + 15], base + off, 1))
        if not decoded or decoded[0].address != base + off:
            raise Unsupported("undecodable byte at %#x" % (base + off))
        insn = decoded[0]
        off += insn.size
        out.append(insn)
    if not out:
        raise Unsupported("empty snippet")
    return out


def _prefixes(insn):
    prefix = list(insn.prefix) + [0, 0, 0, 0]
    lockrep, segment, _opsz, addrsize = prefix[:4]
    if lockrep == 0xF0 or insn.mnemonic.startswith("lock"):
        raise Unsupported("lock prefix rejected at %#x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
    if lockrep in (0xF2, 0xF3):
        raise Unsupported("rep prefix rejected at %#x" % insn.address)
    if segment:
        raise Unsupported("segment override rejected at %#x" % insn.address)
    if addrsize:
        raise Unsupported("address-size override rejected at %#x" % insn.address)


def _xmm(insn, op):
    name = insn.reg_name(op.reg)
    if not name.startswith("xmm"):
        raise Unsupported("expected xmm register at %#x" % insn.address)
    number = int(name[3:])
    if not 0 <= number < 16:
        raise Unsupported("xmm register rejected at %#x" % insn.address)
    return number


def _reg(insn, op):
    name = insn.reg_name(op.reg)
    if name in HIGH_BYTE:
        raise Unsupported("high-byte register %s rejected at %#x" % (name, insn.address))
    if name not in REG_INFO:
        raise Unsupported("register %s rejected at %#x" % (name, insn.address))
    index, bits = REG_INFO[name]
    if op.size * 8 != bits:
        raise Unsupported("register width mismatch for %s at %#x" % (name, insn.address))
    return index, bits


def _mem(insn, op):
    mem = op.mem
    if mem.segment:
        raise Unsupported("segmented memory rejected at %#x" % insn.address)
    if mem.index:
        raise Unsupported("indexed memory rejected at %#x" % insn.address)
    base_name = insn.reg_name(mem.base) if mem.base else ""
    if base_name == "rip":
        ea = (insn.address + insn.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
        return "%#xull" % ea, op.size
    if base_name not in REG_INFO or REG_INFO[base_name][1] != 64:
        raise Unsupported("memory base %s rejected at %#x" % (base_name or "none", insn.address))
    index = REG_INFO[base_name][0]
    if mem.disp:
        return "(rd(c, %d, 64) + (uint64_t)(int64_t)%#x)" % (index, mem.disp), op.size
    return "rd(c, %d, 64)" % index, op.size


def _imm(op, bits):
    return op.imm & ((1 << bits) - 1)


def _mask_expr(bits):
    if bits >= 64:
        return "~0ull"
    return "%#xull" % ((1 << bits) - 1)


def _alu(dst, src_expr, bits, kind, write):
    mask = _mask_expr(bits)
    op = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^"}[kind]
    lines = [
        "{",
        "    uint64_t a_ = rd(c, %d, %d);" % (dst, bits),
        "    uint64_t b_ = %s;" % src_expr,
        "    uint64_t r_ = (a_ %s b_) & %s;" % (op, mask),
    ]
    if kind == "add":
        lines.append("    flags_add(c, a_, b_, r_, %d);" % bits)
    elif kind == "sub":
        lines.append("    flags_sub(c, a_, b_, r_, %d);" % bits)
    else:
        lines.append("    flags_logic(c, r_, %d);" % bits)
    if write:
        lines.append("    wr(c, %d, r_, %d);" % (dst, bits))
    lines.append("}")
    return lines


def _emit(insn):
    mn = insn.mnemonic
    if mn not in ALLOW:
        raise Unsupported("unsupported instruction '%s %s' at %#x" % (mn, insn.op_str, insn.address))
    ops = insn.operands
    comment = "/* %s %s */" % (mn, insn.op_str.strip())
    if mn == "nop":
        if ops:
            raise Unsupported("nop form rejected at %#x" % insn.address)
        return [comment]
    if mn == "push":
        if len(ops) != 1:
            raise Unsupported("push form rejected at %#x" % insn.address)
        src = ops[0]
        if src.type == x86.X86_OP_REG:
            index, bits = _reg(insn, src)
            if bits != 64 or index == 4:
                raise Unsupported("push form rejected at %#x" % insn.address)
            stored = "rd(c, %d, 64)" % index
        elif src.type == x86.X86_OP_IMM:
            stored = "%#xull" % (src.imm & 0xFFFFFFFFFFFFFFFF)
        else:
            raise Unsupported("push form rejected at %#x" % insn.address)
        return [comment,
                "wr(c, 4, rd(c, 4, 64) - 8, 64);",
                "st(mem, rd(c, 4, 64), %s, 8);" % stored]
    if mn == "pop":
        if len(ops) != 1 or ops[0].type != x86.X86_OP_REG:
            raise Unsupported("pop form rejected at %#x" % insn.address)
        index, bits = _reg(insn, ops[0])
        if bits != 64 or index == 4:
            raise Unsupported("pop form rejected at %#x" % insn.address)
        return [comment,
                "wr(c, %d, ld(mem, rd(c, 4, 64), 8), 64);" % index,
                "wr(c, 4, rd(c, 4, 64) + 8, 64);"]
    if len(ops) != 2:
        raise Unsupported("operand form rejected at %#x" % insn.address)
    dst, src = ops
    if mn == "movaps":
        if len(ops) != 2:
            raise Unsupported("movaps form rejected at %#x" % insn.address)
        dst, src = ops
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_REG:
            return [comment, "xmm_copy(c, %d, %d);" % (_xmm(insn, dst), _xmm(insn, src))]
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_MEM:
            ea, _sz = _mem(insn, src)
            return [comment, "xmm_load(c, %d, mem, %s);" % (_xmm(insn, dst), ea)]
        if dst.type == x86.X86_OP_MEM and src.type == x86.X86_OP_REG:
            ea, _sz = _mem(insn, dst)
            return [comment, "xmm_store(c, %d, mem, %s);" % (_xmm(insn, src), ea)]
        raise Unsupported("movaps form rejected at %#x" % insn.address)
    if mn == "lea":
        if len(ops) != 2 or ops[0].type != x86.X86_OP_REG or ops[1].type != x86.X86_OP_MEM:
            raise Unsupported("lea form rejected at %#x" % insn.address)
        index, bits = _reg(insn, ops[0])
        if bits not in (32, 64) or index == 4:
            raise Unsupported("lea form rejected at %#x" % insn.address)
        ea, _size = _mem(insn, ops[1])
        return [comment, "wr(c, %d, %s, %d);" % (index, ea, bits)]
    if mn in ("mov", "movabs"):
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_IMM:
            index, bits = _reg(insn, dst)
            return [comment, "wr(c, %d, %#xull, %d);" % (index, _imm(src, bits), bits)]
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_REG:
            di, db = _reg(insn, dst)
            si, sb = _reg(insn, src)
            if sb > db:
                raise Unsupported("mov narrowing rejected at %#x" % insn.address)
            return [comment, "wr(c, %d, rd(c, %d, %d), %d);" % (di, si, sb, db)]
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_MEM:
            di, db = _reg(insn, dst)
            ea, sz = _mem(insn, src)
            if sz * 8 != db:
                raise Unsupported("mov load width rejected at %#x" % insn.address)
            return [comment, "wr(c, %d, ld(mem, %s, %d), %d);" % (di, ea, sz, db)]
        if dst.type == x86.X86_OP_MEM and src.type == x86.X86_OP_REG:
            ea, sz = _mem(insn, dst)
            si, sb = _reg(insn, src)
            if sz * 8 != sb:
                raise Unsupported("mov store width rejected at %#x" % insn.address)
            return [comment, "st(mem, %s, rd(c, %d, %d), %d);" % (ea, si, sb, sz)]
        if dst.type == x86.X86_OP_MEM and src.type == x86.X86_OP_IMM:
            ea, sz = _mem(insn, dst)
            if sz not in (1, 2, 4, 8):
                raise Unsupported("mov immediate width rejected at %#x" % insn.address)
            return [comment, "st(mem, %s, %#xull, %d);" % (ea, src.imm & ((1 << (sz * 8)) - 1), sz)]
        raise Unsupported("mov form rejected at %#x" % insn.address)
    if mn == "movzx":
        if dst.type != x86.X86_OP_REG or src.type != x86.X86_OP_REG:
            raise Unsupported("movzx memory form rejected at %#x" % insn.address)
        di, db = _reg(insn, dst)
        si, sb = _reg(insn, src)
        if sb >= db:
            raise Unsupported("movzx width rejected at %#x" % insn.address)
        return [comment, "wr(c, %d, rd(c, %d, %d), %d);" % (di, si, sb, db)]
    if mn in ("add", "sub", "and", "or", "xor", "cmp", "test"):
        if dst.type != x86.X86_OP_REG:
            raise Unsupported("%s memory destination rejected at %#x" % (mn, insn.address))
        di, db = _reg(insn, dst)
        if src.type == x86.X86_OP_REG:
            si, sb = _reg(insn, src)
            if sb != db:
                raise Unsupported("%s width mismatch at %#x" % (mn, insn.address))
            src_expr = "rd(c, %d, %d)" % (si, sb)
        elif src.type == x86.X86_OP_IMM and mn in ("add", "sub", "test"):
            src_expr = "%#xull" % _imm(src, db)
        else:
            raise Unsupported("%s form rejected at %#x" % (mn, insn.address))
        kind = {"cmp": "sub", "test": "and"}.get(mn, mn)
        write = mn not in ("cmp", "test")
        return [comment] + _alu(di, src_expr, db, kind, write)
    raise Unsupported("unsupported instruction '%s' at %#x" % (mn, insn.address))


def _validated_insns(code, base):
    if not isinstance(code, (bytes, bytearray)) or isinstance(code, str):
        raise Unsupported("code must be bytes")
    code = bytes(code)
    if code.startswith(b"MZ") or code.startswith(b"PE\0\0"):
        raise Unsupported("refusing to lift a PE image; pass a synthetic instruction fixture")
    if not code or len(code) > MAX_CODE:
        raise Unsupported("snippet length %d is outside 1..%d" % (len(code), MAX_CODE))
    if not isinstance(base, int) or base < 0 or base > 0xFFFFFFFFFFFFFFFF:
        raise Unsupported("bad base")
    insns = _decode(code, base)
    for insn in insns:
        _prefixes(insn)
    if insns[-1].mnemonic == "ret":
        if insns[-1].size != 1 or insns[-1].op_str.strip():
            raise Unsupported("ret form rejected at %#x; only a final one-byte ret is accepted" % insns[-1].address)
        if any(insn.mnemonic == "ret" for insn in insns[:-1]):
            raise Unsupported("ret only allowed as the final instruction")
        # The final ret is a leaf terminator. It is not emitted or executed:
        # a real ret would read the stack, which is not part of this allowlist.
        return code, insns[:-1], insns[-1].address - base
    if any(insn.mnemonic == "ret" for insn in insns):
        raise Unsupported("ret only allowed as the final instruction")
    return code, insns, len(code)


def executed_length(code, base):
    """Bytes emulated before a final one-byte ret. The ret itself is not executed."""
    _code, _insns, length = _validated_insns(code, base)
    return length


def lift_snippet(code, base):
    """Return the C function snippet() for these bytes, or raise Unsupported."""
    _code, insns, _length = _validated_insns(code, base)
    lines = ["void snippet(Cpu64 *c, uint8_t *mem) {", "    (void)c;", "    (void)mem;"]
    for insn in insns:
        for line in _emit(insn):
            lines.append("    " + line)
    lines.append("}")
    return "\n".join(lines) + "\n"
