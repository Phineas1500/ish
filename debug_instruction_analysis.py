#!/usr/bin/env python3
"""
64-bit iSH Instruction Analysis Tool
Analyzes the specific instruction causing SIGILL and helps identify missing components
"""

import struct
import sys

def analyze_rex_prefix(byte):
    """Analyze REX prefix byte (0x40-0x4F)"""
    if not (0x40 <= byte <= 0x4F):
        return None
    
    rex_w = (byte >> 3) & 1  # 64-bit operand size
    rex_r = (byte >> 2) & 1  # ModR/M reg extension  
    rex_x = (byte >> 1) & 1  # SIB index extension
    rex_b = byte & 1         # ModR/M r/m extension
    
    return {
        'raw': byte,
        'W': rex_w, 'R': rex_r, 'X': rex_x, 'B': rex_b,
        'is_64bit': bool(rex_w),
        'extends_reg': bool(rex_r),
        'extends_index': bool(rex_x), 
        'extends_rm': bool(rex_b)
    }

def analyze_modrm(byte, rex_r=0, rex_b=0):
    """Analyze ModR/M byte with REX extensions"""
    mod = (byte >> 6) & 3
    reg = ((byte >> 3) & 7) + (rex_r << 3)
    rm = (byte & 7) + (rex_b << 3)
    
    addressing_modes = {
        0: "register indirect" if rm != 5 else "RIP-relative + disp32",
        1: "register + disp8", 
        2: "register + disp32",
        3: "register direct"
    }
    
    return {
        'raw': byte,
        'mod': mod, 'reg': reg, 'rm': rm,
        'addressing': addressing_modes[mod],
        'is_rip_relative': (mod == 0 and rm == 5)
    }

def analyze_failing_instruction():
    """Analyze the specific instruction that's failing"""
    # From disassembly: 48 8d 3d f9 ff 0b 00
    instruction_bytes = [0x48, 0x8d, 0x3d, 0xf9, 0xff, 0x0b, 0x00]
    
    print("=== FAILING INSTRUCTION ANALYSIS ===")
    print(f"Raw bytes: {' '.join(f'{b:02x}' for b in instruction_bytes)}")
    
    # Analyze REX prefix
    rex = analyze_rex_prefix(instruction_bytes[0])
    print(f"\nREX Prefix (0x{instruction_bytes[0]:02x}):")
    print(f"  W={rex['W']} (64-bit operand: {rex['is_64bit']})")
    print(f"  R={rex['R']} (extends reg field: {rex['extends_reg']})")
    print(f"  X={rex['X']} (extends index: {rex['extends_index']})")  
    print(f"  B={rex['B']} (extends r/m: {rex['extends_rm']})")
    
    # Analyze LEA opcode
    opcode = instruction_bytes[1]
    print(f"\nOpcode (0x{opcode:02x}): LEA (Load Effective Address)")
    
    # Analyze ModR/M
    modrm = analyze_modrm(instruction_bytes[2], rex['R'], rex['B'])
    print(f"\nModR/M (0x{instruction_bytes[2]:02x}):")
    print(f"  mod={modrm['mod']}, reg={modrm['reg']}, r/m={modrm['rm']}")
    print(f"  Addressing: {modrm['addressing']}")
    print(f"  RIP-relative: {modrm['is_rip_relative']}")
    
    # Analyze displacement
    disp32 = struct.unpack('<i', bytes(instruction_bytes[3:7]))[0]
    print(f"\nDisplacement: 0x{disp32 & 0xffffffff:08x} ({disp32})")
    
    print(f"\nInstruction: leaq 0x{disp32 & 0xffffffff:x}(%rip), %rdi")
    print("This loads the effective address of [RIP + displacement] into RDI")
    
    # Identify potential failure points
    print("\n=== POTENTIAL FAILURE POINTS ===")
    print("1. Missing LEA gadget for 64-bit operand size (REX.W=1)")
    print("2. RIP-relative addressing not implemented in gadgets")
    print("3. Incomplete 64-bit register (RDI) handling")
    print("4. Instruction dispatch table missing this specific combination")
    
    return {
        'rex': rex,
        'opcode': opcode,
        'modrm': modrm,
        'displacement': disp32,
        'requires_rip_relative': True,
        'requires_64bit_operands': True,
        'target_register': 'RDI'
    }

if __name__ == "__main__":
    analysis = analyze_failing_instruction()