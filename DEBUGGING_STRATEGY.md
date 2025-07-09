# 🔧 Comprehensive 64-bit iSH Debugging Strategy

## Executive Summary
The 64-bit iSH emulator fails with SIGILL (exit code 132) **after** successful REX prefix parsing. The issue occurs during instruction dispatch/execution of the first 64-bit instruction: `leaq 0xbfff9(%rip), %rdi`.

## Failing Instruction Analysis
```asm
48 8d 3d f9 ff 0b 00    leaq 0xbfff9(%rip), %rdi
```

- **REX.W=1**: Requires 64-bit operand handling
- **RIP-relative**: Uses 64-bit specific addressing mode  
- **Target: RDI**: 64-bit register (reg=7, no extension needed)
- **LEA opcode**: Load Effective Address instruction

## Phase 1: Verify REX Infrastructure ✅ CONFIRMED WORKING

The REX parsing infrastructure is fully implemented and operational:
- REX detection: `(insn & 0xF0) == 0x40` ✅
- Bit extraction: W/R/X/B parsing ✅  
- ModR/M integration: REX-aware decoder ✅
- Operand size: `EFFECTIVE_OZ` macro ✅

## Phase 2: Systematic Root Cause Analysis

### 2.1 Instruction Dispatch Investigation

**Target**: Verify LEA instruction handling in 64-bit mode

```bash
# Check if LEA gadgets exist for 64-bit
grep -r "lea.*64\|LEA.*64" asbestos/gadgets-aarch64/
nm build-64bit/ish | grep -i lea

# Examine instruction dispatch for 0x8d opcode
grep -A 10 -B 5 "case 0x8d" emu/decode.h
```

**Key Questions**:
- Does `case 0x8d:` exist in the 64-bit decoder switch statement?
- Are there 64-bit LEA gadgets available?
- Is `EFFECTIVE_OZ` properly used for LEA instructions?

### 2.2 RIP-Relative Addressing Investigation  

**Target**: Verify RIP-relative addressing implementation

```bash
# Check RIP-relative addressing support
grep -r "rip\|RIP" emu/modrm.h asbestos/gen.c
grep -r "reg_rip" emu/ asbestos/

# Examine addr_rip gadget
nm build-64bit/ish | grep addr_rip
objdump -d build-64bit/ish | grep -A 10 "addr_rip"
```

**Key Questions**:
- Is `reg_rip` properly defined and handled?
- Does `addr_rip` gadget exist and work correctly?
- Is RIP-relative displacement calculation implemented?

### 2.3 64-bit Register Handling Investigation

**Target**: Verify RDI (reg=7) handling in 64-bit mode

```bash
# Check 64-bit register gadgets
nm build-64bit/ish | grep "gadget.*reg_.*di\|gadget.*reg_.*_7"
grep -r "reg_di\|reg_rdi" emu/ asbestos/

# Examine register mapping
grep -r "enum reg64\|enum reg32" emu/cpu.h
```

**Key Questions**:  
- Are 64-bit register variants properly implemented?
- Is RDI correctly mapped in 64-bit mode?
- Do store gadgets exist for 64-bit registers?

### 2.4 Gadget Coverage Analysis

**Target**: Verify specific instruction variant exists

```bash
# Look for LEA + RIP-relative + 64-bit combination
nm build-64bit/ish | grep -E "(lea|addr).*gadget"
grep -A 20 "case 0x8d" emu/decode.h

# Check if gen_addr handles RIP-relative  
grep -A 10 -B 5 "reg_rip" asbestos/gen.c
```

## Phase 3: Advanced Debugging Techniques

### 3.1 Live Debugging with Precise Breakpoints

```bash
# Use the comprehensive debugging script
lldb -s debug_rex_dispatch.lldb

# Manual step-through debugging
lldb build-64bit/ish
(lldb) settings set target.run-args -f alpine-64bit-processed /bin/echo test
(lldb) breakpoint set --file decode.h --line 72 --condition "insn == 0x8d"
(lldb) process launch
```

### 3.2 Instruction Trace Analysis

```bash
# Enable comprehensive instruction tracing
meson configure build-64bit -Dlog="instr strace"
ninja -C build-64bit

# Capture and analyze trace
./build-64bit/ish -f alpine-64bit-processed /bin/echo test 2>&1 | \
  head -n 100 > instruction_trace.log
```

### 3.3 Gadget Availability Testing

**Create minimal test case**:
```c
// test_lea_rip.c - Minimal test for LEA RIP-relative
int main() {
    asm volatile("leaq 0x12345(%rip), %rdi");
    return 0;
}
```

Compile and test:
```bash
gcc -m64 -o test_lea_rip test_lea_rip.c
./build-64bit/ish -f alpine-64bit-processed ./test_lea_rip
```

## Phase 4: Targeted Fixes Based on Findings

### 4.1 If LEA Instruction Handler Missing
- Add `case 0x8d:` to 64-bit decoder with proper `EFFECTIVE_OZ` usage
- Ensure LEA macro supports RIP-relative addressing mode

### 4.2 If RIP-Relative Addressing Incomplete  
- Verify `addr_rip` gadget implementation in `gadgets-aarch64/memory.S`
- Check RIP calculation logic in `gen_addr()` function

### 4.3 If 64-bit Register Gadgets Missing
- Implement missing 64-bit register variants for LEA
- Verify register enum consistency between 32-bit and 64-bit modes

### 4.4 If Gadget Dispatch Table Gaps
- Add missing entries to gadget arrays
- Verify size calculation logic for 64-bit operations

## Phase 5: Verification and Testing

### 5.1 Progressive Testing
1. **Minimal LEA test**: Single LEA instruction
2. **Busybox startup**: First few instructions  
3. **Echo command**: Complete program execution
4. **Complex programs**: Shell, package manager, etc.

### 5.2 Regression Testing
- Ensure 32-bit functionality remains intact
- Verify R8-R15 register functionality still works
- Test various REX prefix combinations

## Expected Outcomes

**Most Likely Root Causes** (in order of probability):
1. **Missing LEA instruction case** for 64-bit in decoder switch statement
2. **Incomplete RIP-relative addressing** in addr_rip gadget  
3. **Missing 64-bit LEA gadget variants** in gadget arrays
4. **Instruction dispatch table gaps** for specific opcode combinations

**Success Criteria**:
- 64-bit build exits with code 0 instead of 132
- LEA RIP-relative instruction executes successfully  
- Busybox startup progresses past first instruction
- No regression in 32-bit functionality

This systematic approach will identify the exact architectural gap causing the post-REX dispatch failure.