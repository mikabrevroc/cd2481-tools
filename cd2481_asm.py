#!/usr/bin/env python3
"""
cd2481_asm.py — CD2481 microcode assembler + decompiler + round-trip verifier

Usage:
    python3 cd2481_asm.py decompile  cd2481_ucode.bin  -o cd2481_ucode.asm
    python3 cd2481_asm.py assemble   cd2481_ucode.asm   -o cd2481_ucode.bin
    python3 cd2481_asm.py verify     cd2481_ucode.bin  cd2481_ucode_recompiled.bin
    python3 cd2481_asm.py roundtrip  cd2481_ucode.bin

The .asm format is designed for lossless round-tripping:
  - Every instruction is either a mnemonic (decoded) or .word (raw 18-bit value)
  - Labels mark all branch targets
  - Padding regions are collapsed into .fill directives
  - Comments annotate known patterns and register accesses

Binary format: 8192 x 18-bit instructions, packed little-endian,
              4 instructions per 9 bytes (72 bits).
"""

import argparse
import hashlib
import re
import sys
from collections import Counter, defaultdict

BITS = 18
INSNS = 8192
MASK = (1 << BITS) - 1
PAD = 0x1E000
SIZE = INSNS * BITS // 8  # 18432

REGISTERS = {
    0x09: "LIVR", 0x10: "COR1", 0x11: "IER", 0x13: "CCR", 0x14: "COR5",
    0x15: "COR4", 0x16: "COR3", 0x17: "COR2", 0x1A: "CSR", 0x1B: "CMR",
    0x1E: "SCHR2", 0x1F: "SCHR1", 0x26: "LICR",
    0x30: "RFOC", 0x40: "ARBADRU", 0x42: "ARBADRL", 0x4A: "ARBCNT",
    0x4F: "ARBSTS", 0x50: "ATBADRU", 0x52: "ATBADRL", 0x5A: "ATBCNT",
    0x5F: "ATBSTS",
    0x80: "TFTC", 0x81: "GFRCR", 0x84: "REOIR", 0x85: "TEOIR",
    0x86: "MEOIR", 0x89: "RISRl", 0x8A: "TISR", 0x8B: "MISR",
    0xC0: "TCOR", 0xC3: "TBPR", 0xC8: "RCOR", 0xCB: "RBPR",
    0xDA: "TPR", 0xDE: "MSVR_RTS", 0xDF: "MSVR_DTR",
    0xE0: "PILR2", 0xE1: "RPILR", 0xE3: "TPILR", 0xE4: "MPILR",
    0xEC: "TIR", 0xED: "RIR", 0xEE: "CAR", 0xEF: "MIR",
    0xF0: "AIRH", 0xF1: "MTCR", 0xF2: "AIRL", 0xF3: "AIRM",
    0xF4: "BTCR_I", 0xF6: "BTCR_M_DMR", 0xF8: "TDR_RDR",
}
REG_BY_NAME = {v: k for k, v in REGISTERS.items()}

OPCODES = {
    0x00: ("NOP",   False),
    0x01: ("B01",   True),
    0x02: ("B02",   True),
    0x03: ("B03",   True),
    0x04: ("B04",   True),
    0x06: ("B06",   True),
    0x07: ("B07",   True),
    0x08: ("B08",   True),
    0x09: ("B09",   True),
    0x0A: ("B0A",   True),
    0x0B: ("B0B",   True),
    0x0C: ("B0C",   True),
    0x0D: ("B0D",   True),
    0x0E: ("B0E",   True),
    0x0F: ("JMP",   True),
    0x10: ("L10",   False),
    0x11: ("L11",   False),
    0x12: ("B12",   True),
    0x13: ("B13",   True),
    0x14: ("B14",   True),
    0x15: ("B15",   True),
    0x16: ("L16",   False),
    0x17: ("B17",   True),
    0x18: ("B18",   True),
    0x19: ("JMPF",  True),
    0x1A: ("L1A",   False),
    0x1B: ("B1B",   True),
    0x1C: ("B1C",   True),
    0x1D: ("B1D",   True),
    0x1E: ("JMP1E", True),
    0x1F: ("B1F",   True),
}
OP_BY_NAME = {}
for op, (name, has_addr) in OPCODES.items():
    OP_BY_NAME[name] = (op, has_addr)


def unpack_insn(blob, i):
    bit = i * BITS
    byte = bit >> 3
    v = 0
    for k in range(3):
        if byte + k < len(blob):
            v |= blob[byte + k] << (8 * k)
    return (v >> (bit & 7)) & MASK


def pack_insn(value, blob, i):
    bit = i * BITS
    byte = bit >> 3
    shift = bit & 7
    clear = ~(MASK << shift) & 0xFFFFFF
    existing = blob[byte] | (blob[byte + 1] << 8) | (blob[byte + 2] << 16)
    existing = (existing & clear) | ((value & MASK) << shift)
    blob[byte] = existing & 0xFF
    blob[byte + 1] = (existing >> 8) & 0xFF
    blob[byte + 2] = (existing >> 16) & 0xFF


def md5sum(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def find_pad_start(insns):
    for i in range(len(insns) - 1, -1, -1):
        if insns[i] != PAD:
            return i + 1
    return 0


def collect_targets(insns, end):
    targets = set()
    for i in range(end):
        op = (insns[i] >> 13) & 0x1F
        name, has_addr = OPCODES.get(op, ("??", False))
        if has_addr:
            addr = insns[i] & 0x1FFF
            if addr < INSNS:
                targets.add(addr)
    targets.add(0)
    if end < INSNS:
        targets.add(end)
    return targets


def reg_name(addr):
    return REGISTERS.get(addr, None)


def disassemble_insn(insn, labels, addr):
    op = (insn >> 13) & 0x1F
    name, has_addr = OPCODES.get(op, (None, None))
    if name is None:
        return f".word 0x{insn:05X}"
    if insn == PAD:
        return "pad"
    if has_addr:
        target = insn & 0x1FFF
        label = labels.get(target, f"0x{target:04X}")
        return f"{name} {label}"
    low8 = insn & 0xFF
    mid8 = (insn >> 8) & 0xFF
    r1 = reg_name(low8)
    r2 = reg_name(mid8)
    if r1 and r2:
        return f"{name} {r1},{r2}"
    elif r1:
        return f"{name} {r1},0x{mid8:02X}"
    elif r2:
        return f"{name} 0x{low8:02X},{r2}"
    else:
        return f"{name} 0x{low8:02X},0x{mid8:02X}"


def annotate(insn, addr, insns, end):
    lines = []
    op = (insn >> 13) & 0x1F
    low8 = insn & 0xFF
    mid8 = (insn >> 8) & 0xFF
    name, has_addr = OPCODES.get(op, ("", False))

    if insn == PAD:
        return []

    if addr == 0x0000:
        lines.append("entry point — microcode starts here")
    if addr == 0x0060:
        lines.append("channel dispatch table — JUMP to 0x1000 (reset handler)")
    if addr == 0x0061:
        lines.append("dispatch to common channel handler at 0x1065")
    if 0x0062 <= addr <= 0x0075 and (addr - 0x0062) % 3 == 0:
        ch = (addr - 0x0062) // 3
        lines.append(f"channel {ch} dispatch — BR_COND to handler")
    if 0x0062 <= addr <= 0x0075 and (addr - 0x0062) % 3 == 1:
        ch = (addr - 0x0062) // 3
        lines.append(f"channel {ch} conditional branch to fast path")
    if addr == 0x007B:
        lines.append("write TEOIR — end transmit interrupt service")
    if addr == 0x007D:
        lines.append("loop back to dispatch for next channel")

    if r1 := reg_name(low8):
        if r1 == "COR1":
            lines.append("COR1: channel option register 1 (data bits, parity)")
        elif r1 == "RFOC":
            lines.append("RFOC: receive FIFO occupancy count")
        elif r1 == "LIVR":
            lines.append("LIVR: local interrupt vector register")
        elif r1 == "TEOIR":
            lines.append("TEOIR: transmit end-of-interrupt register")
        elif r1 == "REOIR":
            lines.append("REOIR: receive end-of-interrupt register")
        elif r1 == "TIR":
            lines.append("TIR: transmit interrupt register (bit 7 = Ten = service pending)")
        elif r1 == "RIR":
            lines.append("RIR: receive interrupt register (bit 7 = Ren = service pending)")
        elif r1 == "CAR":
            lines.append("CAR: channel access register (selects channel 0-3)")
        elif r1 == "AIRH":
            lines.append("AIRH: aux instruction register high (self-ref in microcode?)")

    if r2 := reg_name(mid8):
        if r2 == "ARBADRU":
            lines.append("ARBADRU: DMA receive buffer address (upper)")
        elif r2 == "TCOR":
            lines.append("TCOR: transmit clock option register")
        elif r2 == "RCOR":
            lines.append("RCOR: receive clock option register (bit 7 = TLVal)")
        elif r2 == "CMR":
            lines.append("CMR: channel mode register (async/sync/DMA mode)")
        elif r2 == "LICR":
            lines.append("LICR: local interrupting channel register")

    if name == "JUMP" and has_addr:
        target = insn & 0x1FFF
        if target == 0:
            lines.append("jump to reset/idle")
        elif target == 0x1000:
            lines.append("jump to reset handler at 0x1000")

    return lines


def decompile(blob, outpath):
    insns = [unpack_insn(blob, i) for i in range(INSNS)]
    pad_start = find_pad_start(insns)
    targets = collect_targets(insns, pad_start)

    labels = {}
    for addr in sorted(targets):
        if addr == 0:
            labels[addr] = "entry"
        elif addr == pad_start:
            labels[addr] = "pad_start"
        elif addr == 0x0060:
            labels[addr] = "dispatch_table"
        elif addr == 0x1000:
            labels[addr] = "reset_handler"
        elif 0x0062 <= addr <= 0x0075 and (addr - 0x0062) % 3 == 0:
            ch = (addr - 0x0062) // 3
            labels[addr] = f"chan{ch}_dispatch"
        else:
            labels[addr] = f"L{addr:04X}"

    out = []
    out.append("; CD2481 Microcode — Decompiled Source")
    out.append(f"; Original: cd2481_ucode.bin (18432 bytes, MD5 {md5sum_bytes(blob)})")
    out.append(f"; Format: 8192 x 18-bit instructions, packed LE (4 per 9 bytes)")
    out.append(f"; Hypothesized ISA: [17:13]=opcode(5b) [12:0]=operand(13b)")
    out.append(f"; Known: JUMP 0x3FFF = 0x33FFF (opcode 0x19, confirmed by datasheet)")
    out.append(f"; Real code: 0x0000-0x{pad_start-1:04X} ({pad_start} instructions)")
    out.append(f"; Padding:  0x{pad_start:04X}-0x{INSNS-1:04X} ({INSNS-pad_start} x 0x{PAD:05X})")
    out.append(";")
    out.append("; Register references (Motorola addressing, from nm32a.c):")
    for addr_val in sorted(REGISTERS.keys()):
        out.append(f";   0x{addr_val:02X} = {REGISTERS[addr_val]}")
    out.append(";")
    out.append("; Opcode map (reverse-engineered):")
    for op in sorted(OPCODES.keys()):
        name, has_addr = OPCODES[op]
        flags = "addr" if has_addr else "data"
        out.append(f";   {op:05b} (0x{op:02X}) = {name:<6s} [{flags}]")
    out.append(";")
    out.append("; To reassemble:  python3 cd2481_asm.py assemble <this_file> -o output.bin")
    out.append("")
    out.append(f".total {INSNS}")
    out.append("")

    i = 0
    while i < INSNS:
        if i >= pad_start:
            pad_count = INSNS - i
            out.append(f"; --- padding: {pad_count} x 0x{PAD:05X} ---")
            out.append(f".fill {pad_count}, 0x{PAD:05X}")
            break

        if i in labels:
            if i > 0:
                out.append("")
            out.append(f"; ============================================================")
            region = ""
            if i == 0: region = "Entry point / boot initialization"
            elif i == 0x0060: region = "Channel dispatch table"
            elif 0x007E <= i <= 0x00FF: region = "Per-channel setup"
            elif 0x0100 <= i <= 0x01FF: region = "Interrupt service dispatch"
            elif 0x0200 <= i <= 0x05FF: region = "Register initialization"
            elif 0x0600 <= i <= 0x0FFF: region = "Main protocol handler"
            elif i == 0x1000: region = "Reset handler"
            elif 0x1000 <= i <= 0x14FF: region = "Extended handlers"
            elif 0x1500 <= i <= 0x1FFF: region = "Subroutine library"
            if region:
                out.append(f"; {region}")
            out.append(f"; ============================================================")
            out.append(f"{labels[i]}:")

        insn = insns[i]
        text = disassemble_insn(insn, labels, i)
        notes = annotate(insn, i, insns, pad_start)

        if notes:
            for note in notes:
                out.append(f"    ; {note}")

        if text == "pad":
            run = 1
            while i + run < pad_start and insns[i + run] == PAD:
                run += 1
            if run > 1:
                out.append(f"    .fill {run}, 0x{PAD:05X}")
                i += run
                continue

        out.append(f"    {text}")
        i += 1

    out.append("")
    out.append("; end of microcode")

    text = "\n".join(out) + "\n"
    with open(outpath, 'w') as f:
        f.write(text)
    print(f"decompiled {INSNS} instructions -> {outpath}")
    print(f"  {len(labels)} labels, {pad_start} real + {INSNS-pad_start} padding")
    return text


def md5sum_bytes(data):
    return hashlib.md5(data).hexdigest()


def parse_reg(tok):
    if tok in REG_BY_NAME:
        return REG_BY_NAME[tok]
    return None


def parse_operand(tok, labels, current_addr):
    if tok in labels:
        return labels[tok]
    if tok.startswith("0x") or tok.startswith("0X"):
        return int(tok, 16)
    if tok.startswith("L") and len(tok) == 5:
        try:
            return int(tok[1:], 16)
        except ValueError:
            pass
    try:
        return int(tok, 0)
    except ValueError:
        return None


def assemble(asmpath, outpath):
    with open(asmpath) as f:
        raw_lines = f.readlines()

    parsed = []
    labels = {}

    pc = 0
    for line_no, raw_line in enumerate(raw_lines, 1):
        line = raw_line.split(';')[0].rstrip()
        if not line.strip():
            continue

        stripped = line.strip()

        if stripped.startswith('.total'):
            continue

        if stripped.startswith('.org'):
            parts = stripped.split()
            if len(parts) >= 2:
                pc = int(parts[1], 0)
            parsed.append(('dir', '.org', pc, line_no))
            continue

        if stripped.startswith('.fill'):
            parts = stripped.replace(',', ' ').split()
            count = int(parts[1], 0)
            val = int(parts[2], 0) & MASK
            parsed.append(('fill', count, val, pc, line_no))
            pc += count
            continue

        m = re.match(r'^(\w+):\s*$', stripped)
        if m:
            labels[m.group(1)] = pc
            continue

        m = re.match(r'^(\w+):\s*(.+)$', stripped)
        if m:
            labels[m.group(1)] = pc
            stripped = m.group(2).strip()

        if not stripped:
            continue

        parts = stripped.replace(',', ' ').split()
        parsed.append(('insn', parts, pc, line_no))
        pc += 1

    blob = bytearray(SIZE)
    instructions = {}

    for entry in parsed:
        if entry[0] == 'dir':
            continue
        if entry[0] == 'fill':
            _, count, val, addr, _ = entry
            for k in range(count):
                instructions[addr + k] = val
            continue
        _, parts, pc, line_no = entry

        if parts[0] == '.word':
            instructions[pc] = int(parts[1], 0) & MASK
            continue

        mnem = parts[0].upper()
        if mnem == "PAD":
            instructions[pc] = PAD
            continue

        if mnem in OP_BY_NAME:
            op, has_addr = OP_BY_NAME[mnem]
            if has_addr:
                if len(parts) < 2:
                    raise ValueError(f"line {line_no}: {mnem} needs target")
                target = parse_operand(parts[1], labels, pc)
                if target is None:
                    raise ValueError(f"line {line_no}: cannot resolve '{parts[1]}'")
                val = (op << 13) | (target & 0x1FFF)
            else:
                low = 0
                mid = 0
                if len(parts) >= 2:
                    r = parse_reg(parts[1])
                    if r is not None:
                        low = r
                    else:
                        low = int(parts[1], 0) & 0xFF
                if len(parts) >= 3:
                    r = parse_reg(parts[2])
                    if r is not None:
                        mid = r
                    else:
                        mid = int(parts[2], 0) & 0xFF
                val = (op << 13) | (mid << 8) | low
            instructions[pc] = val
            continue

        raise ValueError(f"line {line_no}: unknown: {' '.join(parts)}")

    for i in range(INSNS):
        pack_insn(instructions.get(i, PAD), blob, i)

    with open(outpath, 'wb') as f:
        f.write(bytes(blob))
    print(f"assembled {pc} instructions -> {outpath} ({len(blob)} bytes)")
    return bytes(blob)


def verify(orig_path, recomp_path):
    orig = open(orig_path, 'rb').read()
    recomp = open(recomp_path, 'rb').read()
    if len(orig) != len(recomp):
        print(f"SIZE MISMATCH: orig={len(orig)} recomp={len(recomp)}")
        return False
    if orig == recomp:
        print(f"IDENTICAL: {len(orig)} bytes match byte-for-byte")
        print(f"  MD5: {md5sum(orig_path)}")
        return True
    diffs = 0
    first_diff = None
    for i in range(len(orig)):
        if orig[i] != recomp[i]:
            diffs += 1
            if first_diff is None:
                first_diff = i
    print(f"MISMATCH: {diffs} bytes differ, first at offset 0x{first_diff:04X}")
    insn_idx = (first_diff * 8) // BITS
    print(f"  (instruction ~0x{insn_idx:04X})")
    print(f"  orig:  {orig[first_diff:first_diff+9].hex()}")
    print(f"  recomp:{recomp[first_diff:first_diff+9].hex()}")
    return False


def roundtrip(binpath):
    import tempfile
    import os
    asm_path = binpath.replace('.bin', '.asm')
    recomp_path = binpath.replace('.bin', '_recompiled.bin')

    decompile(open(binpath, 'rb').read(), asm_path)
    assemble(asm_path, recomp_path)
    ok = verify(binpath, recomp_path)

    if ok:
        print()
        print("ROUND-TRIP SUCCESS: decompile → assemble → byte-identical binary")
    else:
        print()
        print("ROUND-TRIP FAILED: output does not match original")
    return ok


def main():
    ap = argparse.ArgumentParser(
        description="CD2481 microcode assembler/decompiler/verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s decompile  cd2481_ucode.bin -o cd2481_ucode.asm
  %(prog)s assemble   cd2481_ucode.asm  -o cd2481_ucode_recompiled.bin
  %(prog)s verify     cd2481_ucode.bin  cd2481_ucode_recompiled.bin
  %(prog)s roundtrip  cd2481_ucode.bin
        """)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_dec = sub.add_parser('decompile', help='decompile .bin to .asm')
    p_dec.add_argument('input')
    p_dec.add_argument('-o', '--output', required=True)

    p_asm = sub.add_parser('assemble', help='assemble .asm to .bin')
    p_asm.add_argument('input')
    p_asm.add_argument('-o', '--output', required=True)

    p_ver = sub.add_parser('verify', help='compare two .bin files')
    p_ver.add_argument('original')
    p_ver.add_argument('recompiled')

    p_rt = sub.add_parser('roundtrip', help='full decompile→assemble→verify cycle')
    p_rt.add_argument('input')

    args = ap.parse_args()

    if args.cmd == 'decompile':
        blob = open(args.input, 'rb').read()
        if len(blob) != SIZE:
            print(f"WARNING: expected {SIZE} bytes, got {len(blob)}")
        decompile(blob, args.output)

    elif args.cmd == 'assemble':
        assemble(args.input, args.output)

    elif args.cmd == 'verify':
        verify(args.original, args.recompiled)

    elif args.cmd == 'roundtrip':
        roundtrip(args.input)


if __name__ == '__main__':
    main()
