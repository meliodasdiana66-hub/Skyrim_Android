"""Allowlisted x86-64 to C lifter for synthetic fixtures.

Refuses PE images, LOCK, REP, segment and address-size overrides, and any
instruction outside the allowlist. This is not tools/lift.py and it does not
accept a PE32 or PE32+ file.
"""
import capstone
from capstone import x86

MAX_CODE = 4096

ALLOW = frozenset({"nop", "mov", "movabs", "movzx", "add", "sub", "cmp", "and", "or", "xor", "test"})

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
    if len(ops) != 2:
        raise Unsupported("operand form rejected at %#x" % insn.address)
    dst, src = ops
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
        elif src.type == x86.X86_OP_IMM and mn == "add":
            src_expr = "%#xull" % _imm(src, db)
        else:
            raise Unsupported("%s form rejected at %#x" % (mn, insn.address))
        kind = {"cmp": "sub", "test": "and"}.get(mn, mn)
        write = mn not in ("cmp", "test")
        return [comment] + _alu(di, src_expr, db, kind, write)
    raise Unsupported("unsupported instruction '%s' at %#x" % (mn, insn.address))


def lift_snippet(code, base):
    """Return the C function snippet() for these bytes, or raise Unsupported."""
    if not isinstance(code, (bytes, bytearray)) or isinstance(code, str):
        raise Unsupported("code must be bytes")
    code = bytes(code)
    if code.startswith(b"MZ") or code.startswith(b"PE\0\0"):
        raise Unsupported("refusing to lift a PE image; pass a synthetic instruction fixture")
    if not code or len(code) > MAX_CODE:
        raise Unsupported("snippet length %d is outside 1..%d" % (len(code), MAX_CODE))
    if not isinstance(base, int) or base < 0 or base > 0xFFFFFFFFFFFFFFFF:
        raise Unsupported("bad base")
    lines = ["void snippet(Cpu64 *c, uint8_t *mem) {", "    (void)c;", "    (void)mem;"]
    for insn in _decode(code, base):
        _prefixes(insn)
        for line in _emit(insn):
            lines.append("    " + line)
    lines.append("}")
    return "\n".join(lines) + "\n"
