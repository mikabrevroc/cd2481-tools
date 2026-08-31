# cd2481-tools

Reverse-engineering toolchain for the Cirrus Logic CD2481 UART microcode used in Cisco's NM-32A 32-port async network module on the 2811 router.

The CD2481 has no protocol code in ROM — its on-chip RISC processor is inert until a host downloads 8192 18-bit microcode words. This project provides a decompiler and assembler that produce editable source and round-trip back to a byte-identical binary.

## Files

| File | Description |
|---|---|
| `cd2481_asm.py` | Assembler + decompiler + round-trip verifier |
| `cd2481_ucode.bin` | Original firmware (18432 bytes, MD5 `4c487530fb0785c69b8f88df2e274762`) |
| `cd2481_ucode.asm` | Decompiled source (16085 lines, 1330 labels) |
| `gen_ucode_header.py` | Converts .bin to C header for kernel compilation |
| `extract_cd2481_ucode.py` | Extracts microcode from IOS images |
| `nm32a.c` | Linux kernel driver (documents all register addresses) |
| `FINDINGS.md` | Hardware reverse-engineering notes |
| `firmware_README.md` | Firmware provenance documentation |

## Usage

```
# Decompile binary to editable assembly source
python3 cd2481_asm.py decompile  cd2481_ucode.bin  -o cd2481_ucode.asm

# Reassemble source to binary
python3 cd2481_asm.py assemble   cd2481_ucode.asm   -o cd2481_ucode_recompiled.bin

# Verify two binaries are byte-identical
python3 cd2481_asm.py verify     cd2481_ucode.bin   cd2481_ucode_recompiled.bin

# Full decompile → assemble → verify cycle
python3 cd2481_asm.py roundtrip  cd2481_ucode.bin
```

## Binary format

- 8192 instructions × 18 bits, packed little-endian (4 instructions per 9 bytes)
- 8142 real instructions + 50 padding (`0x1E000`)
- Instruction format (hypothesized): `[17:13]` = 5-bit opcode, `[12:0]` = 13-bit operand

## Round-trip

```
decompiled 8192 instructions -> cd2481_ucode.asm
  1330 labels, 8142 real + 50 padding
assembled 8141 instructions -> cd2481_ucode_recompiled.bin (18432 bytes)
IDENTICAL: 18432 bytes match byte-for-byte
  MD5: 4c487530fb0785c69b8f88df2e274762
```

## Provenance

`cd2481_ucode.bin` is Cisco firmware extracted unmodified from IOS image `c2800nm-advipservicesk9-mz.124-24.T3.bin` for interoperability. See `firmware_README.md`.

## Licence

- Tools (`cd2481_asm.py`, `extract_cd2481_ucode.py`, `gen_ucode_header.py`): MIT
- `cd2481_ucode.bin`: Cisco's firmware, extracted unmodified; no claim made
- `nm32a.c`: GPL-2.0 (Linux kernel derivative)
