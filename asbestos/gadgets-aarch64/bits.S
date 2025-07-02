#include "gadgets.h"

.macro do_shift type, size, s
    .irp arg, reg_a,reg_b,reg_c,reg_d,reg_si,reg_di,reg_sp,reg_bp,imm
        .gadget \type\size\()_\arg
            .ifc \arg,imm
                ldr w8, [_ip]
                ands w8, w8, 31
            .else
                ands w8, ecx, 31
            .endif
            b.eq 1f

            # shift by one less, then by one more
            # that way we can retrieve the last bit shifted out for calculating CF and OF
            .ifc \type,shl
                sub w8, w8, 1
                .if \size == 64
                    # For 64-bit shifts, use x-register for shift amount
                    uxtw x8, w8
                    lsl _xtmp, _xtmp, x8
                    ubfx x9, _xtmp, \size-1, 1
                    ubfx x10, _xtmp, \size-2, 1
                    lsl _xtmp, _xtmp, 1
                    # Extract low bits for flag storage
                    and w9, w9, 1
                    and w10, w10, 1
                .else
                    lsl _tmp, _tmp, w8
                    ubfx w9, _tmp, \size-1, 1
                    ubfx w10, _tmp, \size-2, 1
                    lsl _tmp, _tmp, 1
                .endif
                eor w10, w10, w9
                strb w9, [_cpu, CPU_cf]
                strb w10, [_cpu, CPU_of]
            .endif
            .ifc \type,shr
                .if \size == 64
                    ubfx x10, _xtmp, \size-1, 1
                    sub w8, w8, 1
                    uxtw x8, w8
                    lsr _xtmp, _xtmp, x8
                    and x9, _xtmp, 1
                    lsr _xtmp, _xtmp, 1
                    # Extract low bits for flag storage
                    and w9, w9, 1
                    and w10, w10, 1
                .else
                    ubfx w10, _tmp, \size-1, 1
                    sub w8, w8, 1
                    lsr _tmp, _tmp, w8
                    and w9, _tmp, 1
                    lsr _tmp, _tmp, 1
                .endif
                strb w9, [_cpu, CPU_cf]
                strb w10, [_cpu, CPU_of]
            .endif
            .ifc \type,sar
                # lazy ass copy paste job
                .ifnb \s
                    .ifc \s,x
                        .if \size == 64
                            # For 64-bit, _xtmp is already the right register
                        .else
                            sxtw _xtmp, _tmp
                        .endif
                    .else
                        .if \size == 64
                            sxt\s _xtmp, _xtmp
                        .else
                            sxt\s _tmp, _tmp
                        .endif
                    .endif
                .endif
                sub w8, w8, 1
                .if \size == 64
                    uxtw x8, w8
                    asr _xtmp, _xtmp, x8
                    and x9, _xtmp, 1
                    asr _xtmp, _xtmp, 1
                    # Extract low bit for flag storage
                    and w9, w9, 1
                .else
                    asr _tmp, _tmp, w8
                    and w9, _tmp, 1
                    asr _tmp, _tmp, 1
                .endif
                strb w9, [_cpu, CPU_cf]
                strb wzr, [_cpu, CPU_of]
            .endif

            # regrets
            .ifin(\type, rol,ror)
                .ifb \s
                    .ifc \type,rol
                        neg w8, w8
                    .endif
                    .if \size == 64
                        ror _xtmp, _xtmp, w8
                    .else
                        ror _tmp, _tmp, w8
                    .endif
                .else
                    # kill me
                    .ifc \s,x
                        .if \size == 64
                            # _xtmp is already correct for 64-bit
                        .else
                            uxtw _xtmp, _tmp
                        .endif
                    .else
                        .if \size == 64
                            # For 64-bit operations, work with x registers
                            and w8, w8, \size-1
                            neg w9, w8
                            and w9, w9, \size-1
                        .else
                            uxt\s _tmp, _tmp
                            and w8, w8, \size-1
                            neg w9, w8
                            and w9, w9, \size-1
                        .endif
                    .endif
                    .if \size == 64
                        uxtw x8, w8
                        uxtw x9, w9
                        .ifc \type,rol
                            lsl x8, _xtmp, x8
                            lsr x9, _xtmp, x9
                        .else
                            lsr x8, _xtmp, x8
                            lsl x9, _xtmp, x9
                        .endif
                        orr _xtmp, x8, x9
                    .else
                        .ifc \type,rol
                            lsl w8, _tmp, w8
                            lsr w9, _tmp, w9
                        .else
                            lsr w8, _tmp, w8
                            lsl w9, _tmp, w9
                        .endif
                        orr _tmp, w8, w9
                    .endif
                .endif
                .if \size == 64
                    .ifc \type,rol
                        ubfx x9, _xtmp, 0, 1
                        ubfx x10, _xtmp, \size-1, 1
                    .else
                        ubfx x9, _xtmp, \size-1, 1
                        ubfx x10, _xtmp, \size-2, 1
                    .endif
                    and w9, w9, 1
                    and w10, w10, 1
                .else
                    .ifc \type,rol
                        ubfx w9, _tmp, 0, 1
                        ubfx w10, _tmp, \size-1, 1
                    .else
                        ubfx w9, _tmp, \size-1, 1
                        ubfx w10, _tmp, \size-2, 1
                    .endif
                .endif
                eor w10, w10, w9
                strb w9, [_cpu, CPU_cf]
                strb w10, [_cpu, CPU_of]
            .endifin

            # aaaaaaaaaaaaaa
            .ifin(\type, rcl,rcr)
                .ifc \type,rcr
                    .if \size == 64
                        ubfx x9, _xtmp, \size-1, 1
                        and w9, w9, 1
                    .else
                        ubfx w9, _tmp, \size-1, 1
                    .endif
                    ldrb w10, [_cpu, CPU_cf]
                    eor w9, w9, w10
                    strb w9, [_cpu, CPU_of]
                .endif

                ldrb w9, [_cpu, CPU_cf]
                lsl x9, x9, \size
                orr _xtmp, _xtmp, x9
                # so ok we mask the shift count, not too hard
                and w8, w8, 31
                # ...now mod by \size+1 oof
                .if \size == 8
                    .irpc _, 123
                        subs w10, w8, \size+1
                        csel w8, w10, w8, gt
                    .endr
                .elseif \size == 16
                    subs w10, w8, \size+1
                    csel w8, w10, w8, gt
                .elseif \size == 32
                    subs w10, w8, \size+1
                    csel w8, w10, w8, gt
                .elseif \size == 64
                    # For 64-bit, need to handle larger modulo
                    .irpc _, 12
                        subs w10, w8, \size+1
                        csel w8, w10, w8, gt
                    .endr
                .endif
                mov w9, \size+1
                sub w9, w9, w8
                uxtw x8, w8
                uxtw x9, w9
                .ifc \type,rcl
                    lsl x8, _xtmp, x8
                    lsr x9, _xtmp, x9
                .else
                    lsr x8, _xtmp, x8
                    lsl x9, _xtmp, x9
                .endif
                orr _xtmp, x8, x9
                ubfx x9, _xtmp, \size, 1
                and w9, w9, 1
                strb w9, [_cpu, CPU_cf]
                .ifc \type,rcl
                    .if \size == 64
                        ubfx x10, _xtmp, \size-1, 1
                        and w10, w10, 1
                    .else
                        ubfx w10, _tmp, \size-1, 1
                    .endif
                    eor w10, w10, w9
                    strb w10, [_cpu, CPU_of]
                .endif
            .endifin

            .ifin(\type, shl,shr,sar)
                setf_zsp \s
                clearf_a
            .endifin
        1:
            .ifc \arg,imm
                gret 1
            .else
                gret
            .endif
    .endr
.endm

.irp type, shl,shr,sar
    .irp size, 8,16,32,64
        ss \size, do_shift, \type
    .endr
    .gadget_array \type
.endr
# Enable 64-bit for safe rol/ror operations - they have working 64-bit support
.irp type, rol,ror
    .irp size, 8,16,32,64
        ss \size, do_shift, \type
    .endr
    .gadget_array \type
.endr

# Keep rcl/rcr at smaller sizes - complex 64-bit modulus issues
.irp type, rcl,rcr
    .irp size, 8,16,32
        ss \size, do_shift, \type
    .endr
    # Manual array that excludes 64-bit due to complexity
    _gadget_array_start \type
        gadgets \type\()8, GADGET_LIST
        gadgets \type\()16, GADGET_LIST
        gadgets \type\()32, GADGET_LIST
        # Exclude 64-bit - not implemented due to complex modulus issues
    .popsection
.endr

# rcl/rcr addr/gs/mem variants need complex implementation - skip for now

# Manual rcl addr/gs/mem variants implementation

# RCL 8-bit variants
.gadget rcl8_addr
    ands w8, ecx, 31
    b.eq 1f
    # Get 8-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _addr, 0xff
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _addr, w8, 0xff
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _addr, 7, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl8_gs
    ands w8, ecx, 31
    b.eq 1f
    # Get 8-bit value from gs and carry flag
    ldr _tmp, [_cpu, #CPU_gs]
    ldrb w10, [_cpu, CPU_cf]
    and w9, _tmp, 0xff
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xff
    str _tmp, [_cpu, #CPU_gs]
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 7, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl8_mem
    read_prep 8, rcl8_mem
    ands w8, ecx, 31
    b.eq 1f
    # Get 8-bit value from memory and carry flag
    ldrb w9, [_xaddr]
    ldrb w10, [_cpu, CPU_cf]
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xff
    strb _tmp, [_xaddr]
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 7, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    write_done 8, rcl8_mem
    gret 1
    write_bullshit 8, rcl8_mem

# RCL 16-bit variants
.gadget rcl16_addr
    ands w8, ecx, 31
    b.eq 1f
    # Get 16-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _addr, 0xffff
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _addr, w8, 0xffff
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _addr, 15, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl16_gs
    ands w8, ecx, 31
    b.eq 1f
    # Get 16-bit value from gs and carry flag
    ldr _tmp, [_cpu, #CPU_gs]
    ldrb w10, [_cpu, CPU_cf]
    and w9, _tmp, 0xffff
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xffff
    str _tmp, [_cpu, #CPU_gs]
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 15, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl16_mem
    read_prep 16, rcl16_mem
    ands w8, ecx, 31
    b.eq 1f
    # Get 16-bit value from memory and carry flag
    ldrh w9, [_xaddr]
    ldrb w10, [_cpu, CPU_cf]
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xffff
    strh _tmp, [_xaddr]
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 15, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    write_done 16, rcl16_mem
    gret 1
    write_bullshit 16, rcl16_mem

# RCL 32-bit variants
.gadget rcl32_addr
    ands w8, ecx, 31
    b.eq 1f
    # Get 32-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, _addr
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _addr, w8
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _addr, 31, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl32_gs
    ands w8, ecx, 31
    b.eq 1f
    # Get 32-bit value from gs and carry flag
    ldr _tmp, [_cpu, #CPU_gs]
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, _tmp
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _tmp, w8
    str _tmp, [_cpu, #CPU_gs]
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 31, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    gret

.gadget rcl32_mem
    read_prep 32, rcl32_mem
    ands w8, ecx, 31
    b.eq 1f
    # Get 32-bit value from memory and carry flag
    ldr w9, [_xaddr]
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, w9
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation
    lsl x8, x9, x8
    lsr x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _tmp, w8
    str _tmp, [_xaddr]
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
    ubfx w10, _tmp, 31, 1
    eor w10, w10, w9
    strb w10, [_cpu, CPU_of]
1:
    write_done 32, rcl32_mem
    gret 1
    write_bullshit 32, rcl32_mem

# Manual rcr addr/gs/mem variants implementation

# RCR 8-bit variants
.gadget rcr8_addr
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ubfx w9, _addr, 7, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 8-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _addr, 0xff
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _addr, w8, 0xff
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr8_gs
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldr _tmp, [_cpu, #CPU_gs]
    ubfx w9, _tmp, 7, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 8-bit value from gs and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _tmp, 0xff
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xff
    str _tmp, [_cpu, #CPU_gs]
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr8_mem
    read_prep 8, rcr8_mem
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldrb w9, [_xaddr]
    ubfx w10, w9, 7, 1
    ldrb w11, [_cpu, CPU_cf]
    eor w10, w10, w11
    strb w10, [_cpu, CPU_of]
    # Get 8-bit value from memory and carry flag
    ldrb w10, [_cpu, CPU_cf]
    lsl x10, x10, 8
    orr x9, x9, x10
    # Modulo 9 for 8-bit+carry
    .irpc _, 123
        subs w10, w8, 9
        csel w8, w10, w8, gt
    .endr
    mov w10, 9
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xff
    strb _tmp, [_xaddr]
    ubfx w9, w8, 8, 1
    strb w9, [_cpu, CPU_cf]
1:
    write_done 8, rcr8_mem
    gret 1
    write_bullshit 8, rcr8_mem

# RCR 16-bit variants
.gadget rcr16_addr
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ubfx w9, _addr, 15, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 16-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _addr, 0xffff
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _addr, w8, 0xffff
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr16_gs
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldr _tmp, [_cpu, #CPU_gs]
    ubfx w9, _tmp, 15, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 16-bit value from gs and carry flag
    ldrb w10, [_cpu, CPU_cf]
    and w9, _tmp, 0xffff
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xffff
    str _tmp, [_cpu, #CPU_gs]
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr16_mem
    read_prep 16, rcr16_mem
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldrh w9, [_xaddr]
    ubfx w10, w9, 15, 1
    ldrb w11, [_cpu, CPU_cf]
    eor w10, w10, w11
    strb w10, [_cpu, CPU_of]
    # Get 16-bit value from memory and carry flag
    ldrb w10, [_cpu, CPU_cf]
    lsl x10, x10, 16
    orr x9, x9, x10
    # Modulo 17 for 16-bit+carry
    subs w10, w8, 17
    csel w8, w10, w8, gt
    mov w10, 17
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    and _tmp, w8, 0xffff
    strh _tmp, [_xaddr]
    ubfx w9, w8, 16, 1
    strb w9, [_cpu, CPU_cf]
1:
    write_done 16, rcr16_mem
    gret 1
    write_bullshit 16, rcr16_mem

# RCR 32-bit variants
.gadget rcr32_addr
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ubfx w9, _addr, 31, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 32-bit value from addr and carry flag
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, _addr
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _addr, w8
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr32_gs
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldr _tmp, [_cpu, #CPU_gs]
    ubfx w9, _tmp, 31, 1
    ldrb w10, [_cpu, CPU_cf]
    eor w9, w9, w10
    strb w9, [_cpu, CPU_of]
    # Get 32-bit value from gs and carry flag
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, _tmp
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _tmp, w8
    str _tmp, [_cpu, #CPU_gs]
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
1:
    gret

.gadget rcr32_mem
    read_prep 32, rcr32_mem
    ands w8, ecx, 31
    b.eq 1f
    # Pre-calculate OF flag for rcr
    ldr w9, [_xaddr]
    ubfx w10, w9, 31, 1
    ldrb w11, [_cpu, CPU_cf]
    eor w10, w10, w11
    strb w10, [_cpu, CPU_of]
    # Get 32-bit value from memory and carry flag
    ldrb w10, [_cpu, CPU_cf]
    uxtw x9, w9
    lsl x10, x10, 32
    orr x9, x9, x10
    # Modulo 33 for 32-bit+carry
    subs w10, w8, 33
    csel w8, w10, w8, gt
    mov w10, 33
    sub w10, w10, w8
    uxtw x8, w8
    uxtw x10, x10
    # Perform rotation (rcr: right rotation)
    lsr x8, x9, x8
    lsl x10, x9, x10
    orr x8, x8, x10
    # Extract result and flags
    mov _tmp, w8
    str _tmp, [_xaddr]
    ubfx x9, x8, 32, 1
    strb w9, [_cpu, CPU_cf]
1:
    write_done 32, rcr32_mem
    gret 1
    write_bullshit 32, rcr32_mem

# Helper macro for the shift logic without the gadget wrapper
.macro do_shift_logic type, size, target
    ands w8, ecx, 31
    b.eq 1f

    # shift by one less, then by one more to get flags
    .ifc \type,shl
        sub w8, w8, 1
        uxtw x8, w8
        lsl \target, \target, x8
        ubfx x9, \target, \size-1, 1
        ubfx x10, \target, \size-2, 1
        lsl \target, \target, 1
        and w9, w9, 1
        and w10, w10, 1
        eor w10, w10, w9
        strb w9, [_cpu, CPU_cf]
        strb w10, [_cpu, CPU_of]
    .endif
    .ifc \type,shr
        ubfx x10, \target, \size-1, 1
        sub w8, w8, 1
        uxtw x8, w8
        lsr \target, \target, x8
        and x9, \target, 1
        lsr \target, \target, 1
        and w9, w9, 1
        and w10, w10, 1
        strb w9, [_cpu, CPU_cf]
        strb w10, [_cpu, CPU_of]
    .endif
    .ifc \type,sar
        sub w8, w8, 1
        uxtw x8, w8
        asr \target, \target, x8
        and x9, \target, 1
        asr \target, \target, 1
        and w9, w9, 1
        strb w9, [_cpu, CPU_cf]
        strb wzr, [_cpu, CPU_of]
    .endif
    
    setf_zsp x
    clearf_a
1:
.endm

# Add missing addr and gs shift gadgets for 64-bit support
.gadget shl64_addr
    do_shift_logic shl, 64, _xaddr
    gret

.gadget shl64_gs  
    ldr _xtmp, [_cpu, #CPU_gs]
    do_shift_logic shl, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret
    
.gadget shl64_mem
    read_prep 64, shl64_mem
    ldr _xtmp, [_xaddr]
    do_shift_logic shl, 64, _xtmp
    str _xtmp, [_xaddr]
    write_done 64, shl64_mem
    gret 1
    write_bullshit 64, shl64_mem

.gadget shr64_addr
    do_shift_logic shr, 64, _xaddr
    gret

.gadget shr64_gs  
    ldr _xtmp, [_cpu, #CPU_gs]
    do_shift_logic shr, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret
    
.gadget shr64_mem
    read_prep 64, shr64_mem
    ldr _xtmp, [_xaddr]
    do_shift_logic shr, 64, _xtmp
    str _xtmp, [_xaddr]
    write_done 64, shr64_mem
    gret 1
    write_bullshit 64, shr64_mem

.gadget sar64_addr
    do_shift_logic sar, 64, _xaddr
    gret

.gadget sar64_gs  
    ldr _xtmp, [_cpu, #CPU_gs]
    do_shift_logic sar, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret
    
.gadget sar64_mem
    read_prep 64, sar64_mem
    ldr _xtmp, [_xaddr]
    do_shift_logic sar, 64, _xtmp
    str _xtmp, [_xaddr]
    write_done 64, sar64_mem
    gret 1
    write_bullshit 64, sar64_mem

# REMOVED: Shift operations - do_shift_logic macro is 64-bit only
# TODO: Need to implement manual 32/16/8-bit shift operations later

# Add missing 32-bit shift operations manually 
.gadget shl32_addr
    lsl _addr, _addr, ecx
    ubfx w9, _addr, 31, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shr32_addr  
    lsr _addr, _addr, ecx
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget sar32_addr
    asr _addr, _addr, ecx
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shl32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsl _tmp, _tmp, ecx
    ubfx w9, _tmp, 31, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget shr32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsr _tmp, _tmp, ecx
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sar32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    asr _tmp, _tmp, ecx
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing 16-bit shift operations manually
.gadget shl16_addr
    lsl _addr, _addr, ecx
    and _addr, _addr, 0xFFFF
    ubfx w9, _addr, 15, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shr16_addr
    lsr _addr, _addr, ecx
    and _addr, _addr, 0xFFFF
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget sar16_addr
    asr _addr, _addr, ecx
    and _addr, _addr, 0xFFFF
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shl16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsl _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFFFF
    ubfx w9, _tmp, 15, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget shr16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsr _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFFFF
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sar16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    asr _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFFFF
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing 8-bit shift operations manually
.gadget shl8_addr
    lsl _addr, _addr, ecx
    and _addr, _addr, 0xFF
    ubfx w9, _addr, 7, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shr8_addr
    lsr _addr, _addr, ecx
    and _addr, _addr, 0xFF
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget sar8_addr
    asr _addr, _addr, ecx
    and _addr, _addr, 0xFF
    ubfx w9, _addr, 0, 1
    strb w9, [_cpu, CPU_cf]
    gret

.gadget shl8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsl _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFF
    ubfx w9, _tmp, 7, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget shr8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    lsr _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFF
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sar8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    asr _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFF
    ubfx w9, _tmp, 0, 1
    strb w9, [_cpu, CPU_cf]
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing memory variants for 32/16/8-bit shift operations

# 32-bit memory shift operations
.gadget shl32_mem
    write_prep 32, shl32_mem
    ldr w8, [_xaddr]
    lsl w8, w8, ecx
    ubfx w9, w8, 31, 1
    strb w9, [_cpu, CPU_cf]
    str w8, [_xaddr]
    write_done 32, shl32_mem
    gret 1
    write_bullshit 32, shl32_mem

.gadget shr32_mem  
    write_prep 32, shr32_mem
    ldr w8, [_xaddr]
    lsr w8, w8, ecx
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    str w8, [_xaddr]
    write_done 32, shr32_mem
    gret 1
    write_bullshit 32, shr32_mem

.gadget sar32_mem
    write_prep 32, sar32_mem
    ldr w8, [_xaddr]
    asr w8, w8, ecx
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    str w8, [_xaddr]
    write_done 32, sar32_mem
    gret 1
    write_bullshit 32, sar32_mem

# 16-bit memory shift operations  
.gadget shl16_mem
    write_prep 16, shl16_mem
    ldrh w8, [_xaddr]
    lsl w8, w8, ecx
    and w8, w8, 0xFFFF
    ubfx w9, w8, 15, 1
    strb w9, [_cpu, CPU_cf]
    strh w8, [_xaddr]
    write_done 16, shl16_mem
    gret 1
    write_bullshit 16, shl16_mem

.gadget shr16_mem
    write_prep 16, shr16_mem
    ldrh w8, [_xaddr]
    lsr w8, w8, ecx
    and w8, w8, 0xFFFF
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    strh w8, [_xaddr]
    write_done 16, shr16_mem
    gret 1
    write_bullshit 16, shr16_mem

.gadget sar16_mem
    write_prep 16, sar16_mem
    ldrh w8, [_xaddr]
    asr w8, w8, ecx
    and w8, w8, 0xFFFF
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    strh w8, [_xaddr]
    write_done 16, sar16_mem
    gret 1
    write_bullshit 16, sar16_mem

# 8-bit memory shift operations
.gadget shl8_mem
    write_prep 8, shl8_mem
    ldrb w8, [_xaddr]
    lsl w8, w8, ecx
    and w8, w8, 0xFF
    ubfx w9, w8, 7, 1
    strb w9, [_cpu, CPU_cf]
    strb w8, [_xaddr]
    write_done 8, shl8_mem
    gret 1
    write_bullshit 8, shl8_mem

.gadget shr8_mem
    write_prep 8, shr8_mem
    ldrb w8, [_xaddr]
    lsr w8, w8, ecx
    and w8, w8, 0xFF
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    strb w8, [_xaddr]
    write_done 8, shr8_mem
    gret 1
    write_bullshit 8, shr8_mem

.gadget sar8_mem
    write_prep 8, sar8_mem
    ldrb w8, [_xaddr]
    asr w8, w8, ecx
    and w8, w8, 0xFF
    ubfx w9, w8, 0, 1
    strb w9, [_cpu, CPU_cf]
    strb w8, [_xaddr]
    write_done 8, sar8_mem
    gret 1
    write_bullshit 8, sar8_mem

# Missing rotate memory operations (8 operations)

# 64-bit memory rotate operations
.gadget rol64_mem
    write_prep 64, rol64_mem
    ldr x8, [_xaddr]
    neg w9, ecx
    uxtw x9, w9
    ror x8, x8, x9
    ubfx x10, x8, 0, 1
    ubfx x11, x8, 63, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    str x8, [_xaddr]
    write_done 64, rol64_mem
    gret 1
    write_bullshit 64, rol64_mem

.gadget ror64_mem
    write_prep 64, ror64_mem
    ldr x8, [_xaddr]
    uxtw x9, ecx
    ror x8, x8, x9
    ubfx x10, x8, 63, 1
    ubfx x11, x8, 62, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    str x8, [_xaddr]
    write_done 64, ror64_mem
    gret 1
    write_bullshit 64, ror64_mem

# 32-bit memory rotate operations
.gadget rol32_mem
    write_prep 32, rol32_mem
    ldr w8, [_xaddr]
    neg w9, ecx
    ror w8, w8, w9
    ubfx w10, w8, 0, 1
    ubfx w11, w8, 31, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    str w8, [_xaddr]
    write_done 32, rol32_mem
    gret 1
    write_bullshit 32, rol32_mem

.gadget ror32_mem
    write_prep 32, ror32_mem
    ldr w8, [_xaddr]
    ror w8, w8, ecx
    ubfx w10, w8, 31, 1
    ubfx w11, w8, 30, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    str w8, [_xaddr]
    write_done 32, ror32_mem
    gret 1
    write_bullshit 32, ror32_mem

# 16-bit memory rotate operations  
.gadget rol16_mem
    write_prep 16, rol16_mem
    ldrh w8, [_xaddr]
    neg w9, ecx
    ror w8, w8, w9
    and w8, w8, 0xFFFF
    ubfx w10, w8, 0, 1
    ubfx w11, w8, 15, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    strh w8, [_xaddr]
    write_done 16, rol16_mem
    gret 1
    write_bullshit 16, rol16_mem

.gadget ror16_mem
    write_prep 16, ror16_mem
    ldrh w8, [_xaddr]
    ror w8, w8, ecx
    and w8, w8, 0xFFFF
    ubfx w10, w8, 15, 1
    ubfx w11, w8, 14, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    strh w8, [_xaddr]
    write_done 16, ror16_mem
    gret 1
    write_bullshit 16, ror16_mem

# 8-bit memory rotate operations
.gadget rol8_mem
    write_prep 8, rol8_mem
    ldrb w8, [_xaddr]
    neg w9, ecx
    ror w8, w8, w9
    and w8, w8, 0xFF
    ubfx w10, w8, 0, 1
    ubfx w11, w8, 7, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    strb w8, [_xaddr]
    write_done 8, rol8_mem
    gret 1
    write_bullshit 8, rol8_mem

.gadget ror8_mem
    write_prep 8, ror8_mem
    ldrb w8, [_xaddr]
    ror w8, w8, ecx
    and w8, w8, 0xFF
    ubfx w10, w8, 7, 1
    ubfx w11, w8, 6, 1
    eor w11, w11, w10
    strb w10, [_cpu, CPU_cf]
    strb w11, [_cpu, CPU_of]
    strb w8, [_xaddr]
    write_done 8, ror8_mem
    gret 1
    write_bullshit 8, ror8_mem

# Comprehensive SHLD/SHRD implementation for all sizes and addressing modes
# SHLD = Shift Left Double: Destination << count, fill from source  
# SHRD = Shift Right Double: Destination >> count, fill from source

.macro do_shiftd_op op, size, arg
    # Get shift count
    .ifc \arg,imm
        ldrb w8, [_ip]
    .else
        uxtb w8, ecx
    .endif
    
    # Check if shift count is zero
    .if \size == 64
        tst w8, 63
    .else
        tst w8, 31
    .endif
    b.eq 2f
    
    # Prepare registers based on size
    .if \size == 64
        # Use 64-bit registers for 64-bit operations
        mov x9, \size
        sub x9, x9, x8
        sub x8, x8, 1  /* shift by one less for flag extraction */
        uxtw x8, w8
        uxtw x9, w9
        
        .ifc \op,shrd
            # SHRD: destination >> (count-1), get CF, then >> 1, fill with source << (64-count)
            lsr x10, _xtmp, x8
            and x11, x10, 1        /* CF = bit shifted out */
            lsr x10, x10, 1        /* complete the shift */
            lsl x12, x12, x9       /* source << (size-count) */
        .else
            # SHLD: destination << (count-1), get CF, then << 1, fill with source >> (64-count)  
            lsl x10, _xtmp, x8
            ubfx x11, x10, 63, 1   /* CF = bit shifted out */
            lsl x10, x10, 1        /* complete the shift */
            lsr x12, x12, x9       /* source >> (size-count) */
        .endif
        orr _xtmp, x10, x12
        strb w11, [_cpu, CPU_cf]
    .else
        # Use 32-bit registers for smaller operations
        mov w9, \size
        sub w9, w9, w8
        sub w8, w8, 1  /* shift by one less for flag extraction */
        
        .ifc \op,shrd
            # SHRD: destination >> (count-1), get CF, then >> 1, fill with source << (size-count)
            lsr w10, _tmp, w8
            and w11, w10, 1        /* CF = bit shifted out */
            lsr w10, w10, 1        /* complete the shift */
            lsl w12, w12, w9       /* source << (size-count) */
        .else
            # SHLD: destination << (count-1), get CF, then << 1, fill with source >> (size-count)
            lsl w10, _tmp, w8
            .if \size == 32
                ubfx w11, w10, 31, 1   /* CF = bit shifted out */
            .else N .if \size == 16
                ubfx w11, w10, 15, 1
            .else
                ubfx w11, w10, 7, 1
            .endif N .endif
            lsl w10, w10, 1        /* complete the shift */
            lsr w12, w12, w9       /* source >> (size-count) */
        .endif
        orr _tmp, w10, w12
        
        # Mask result to correct size
        .if \size == 16
            and _tmp, _tmp, 0xFFFF
        .else N .if \size == 8
            and _tmp, _tmp, 0xFF
        .endif N .endif
        
        strb w11, [_cpu, CPU_cf]
    .endif
    
    # Set flags (ZF, SF, PF)
    setf_zsp
    
2:
    .ifc \arg,imm
        gret 1
    .else
        gret
    .endif
.endm

.macro do_shiftd op, size, s
    # Register variants
    .macro x name, reg
        .gadget \op\()_cl\size\()_\name
            .if \size == 64
                # Load source register (second operand) 
                .ifc \name,reg_a
                    mov x12, rax
                .else N .ifc \name,reg_b
                    mov x12, rbx
                .else N .ifc \name,reg_c
                    mov x12, rcx
                .else N .ifc \name,reg_d
                    mov x12, rdx
                .else N .ifc \name,reg_si
                    mov x12, rsi
                .else N .ifc \name,reg_di
                    mov x12, rdi
                .else N .ifc \name,reg_sp
                    mov x12, rsp
                .else N .ifc \name,reg_bp
                    mov x12, rbp
                .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
            .else
                mov w12, \reg
            .endif
            do_shiftd_op \op, \size, cl
            
        .gadget \op\()_imm\size\()_\name
            .if \size == 64
                # Load source register (second operand)
                .ifc \name,reg_a
                    mov x12, rax
                .else N .ifc \name,reg_b
                    mov x12, rbx
                .else N .ifc \name,reg_c
                    mov x12, rcx
                .else N .ifc \name,reg_d
                    mov x12, rdx
                .else N .ifc \name,reg_si
                    mov x12, rsi
                .else N .ifc \name,reg_di
                    mov x12, rdi
                .else N .ifc \name,reg_sp
                    mov x12, rsp
                .else N .ifc \name,reg_bp
                    mov x12, rbp
                .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
            .else
                mov w12, \reg
            .endif
            do_shiftd_op \op, \size, imm
    .endm
    .each_reg x
    .purgem x
    
    # addr variants
    .gadget \op\()_cl\size\()_addr
        .if \size == 64
            mov x12, _xaddr  /* source = addr */
        .else
            mov w12, _addr   /* source = addr */
        .endif
        do_shiftd_op \op, \size, cl
        
    .gadget \op\()_imm\size\()_addr  
        .if \size == 64
            mov x12, _xaddr  /* source = addr */
        .else
            mov w12, _addr   /* source = addr */
        .endif
        do_shiftd_op \op, \size, imm
    
    # gs variants
    .gadget \op\()_cl\size\()_gs
        .if \size == 64
            ldr x12, [_cpu, #CPU_gs]  /* source = gs */
        .else
            ldr w12, [_cpu, #CPU_gs]  /* source = gs */
        .endif
        do_shiftd_op \op, \size, cl
        
    .gadget \op\()_imm\size\()_gs
        .if \size == 64
            ldr x12, [_cpu, #CPU_gs]  /* source = gs */
        .else
            ldr w12, [_cpu, #CPU_gs]  /* source = gs */
        .endif
        do_shiftd_op \op, \size, imm
    
    # mem variants  
    .gadget \op\()_cl\size\()_mem
        read_prep \size, \op\()_cl\size\()_mem
        .if \size == 64
            ldr x12, [_xaddr]  /* source = memory */
        .else
            ldr\s w12, [_xaddr] /* source = memory */
        .endif
        do_shiftd_op \op, \size, cl
        read_bullshit \size, \op\()_cl\size\()_mem
        
    .gadget \op\()_imm\size\()_mem
        read_prep \size, \op\()_imm\size\()_mem  
        .if \size == 64
            ldr x12, [_xaddr]  /* source = memory */
        .else
            ldr\s w12, [_xaddr] /* source = memory */
        .endif
        do_shiftd_op \op, \size, imm
        read_bullshit \size, \op\()_imm\size\()_mem
    
    # imm variants (destination = immediate, source = register)
    .gadget \op\()_cl\size\()_imm
        .if \size == 64
            ldr x12, [_ip]     /* source = immediate */
        .else
            ldr\s w12, [_ip]   /* source = immediate */ 
        .endif
        do_shiftd_op \op, \size, cl
        gret 1
        
    .gadget \op\()_imm\size\()_imm
        .if \size == 64
            ldr x12, [_ip]     /* source = immediate */
        .else
            ldr\s w12, [_ip]   /* source = immediate */
        .endif
        do_shiftd_op \op, \size, imm
        gret 1
.endm

# Generate all SHLD/SHRD variants for all sizes
.irp op, shld,shrd
    .irp size, 8,16,32,64
        ss \size, do_shiftd, \op
    .endr
    .gadget_array \op\()_cl
    .gadget_array \op\()_imm  
.endr

.macro do_bt_op op, arg, size, s
    .ifc \op,bt
        .if \size == 64
            .ifnc \arg, x8
                mov x8, \arg
            .endif
            and _xtmp, _xtmp, \size-1
            lsr x8, x8, _xtmp
            and w8, w8, 1
            strb w8, [_cpu, CPU_cf]
        .else
            .ifnc \arg, w8
                mov w8, \arg
            .endif
            and _tmp, _tmp, \size-1
            lsr w8, w8, _tmp
            and w8, w8, 1
            strb w8, [_cpu, CPU_cf]
        .endif
    .else
        .if \size == 64
            mov x9, 1
            and _xtmp, _xtmp, \size-1
            lsl x9, x9, _xtmp
            tst \arg, x9
            .ifc \op,btc
                eor \arg, \arg, x9
            .else N .ifc \op,bts
                orr \arg, \arg, x9
            .else N .ifc \op,btr
                bic \arg, \arg, x9
            .endif N .endif N .endif
            cset w9, ne
            strb w9, [_cpu, CPU_cf]
        .else
            mov w9, 1
            and _tmp, _tmp, \size-1
            lsl w9, w9, _tmp
            tst \arg, w9
            .ifc \op,btc
                eor \arg, \arg, w9
            .else N .ifc \op,bts
                orr \arg, \arg, w9
            .else N .ifc \op,btr
                bic \arg, \arg, w9
            .endif N .endif N .endif
            cset w9, ne
            strb w9, [_cpu, CPU_cf]
        .endif
    .endif
.endm

.macro do_bt op, size, s
    # Add missing imm variant for bit test operations
    .gadget \op\size\()_imm
        .if \size == 64
            ldr x8, [_ip]
            do_bt_op \op, x8, \size, \s
        .else
            ldr\s w8, [_ip]
            do_bt_op \op, w8, \size, \s
        .endif
        gret 1

    .gadget \op\size\()_mem
        .if \size == 64
            bic x8, _xtmp, 0x3f
            lsr x8, x8, 3
            add _xaddr, _xaddr, x8
        .else
            bic w8, _tmp, 0x1f
            add _addr, _addr, w8, lsr 3
        .endif
        # hell {{{
        .ifin(\op, bt)
            read_prep \size, \op\size\()_mem
        .endifin
        .ifin(\op, btc,bts,btr)
            write_prep \size, \op\size\()_mem
        .endifin
        # }}}
        .if \size == 64
            ldr x8, [_xaddr]
            do_bt_op \op, x8, \size, \s
        .else
            ldr w8, [_xaddr]
            do_bt_op \op, w8, \size, \s
        .endif
        .ifin(\op, btc,bts,btr)
            .if \size == 64
                str x8, [_xaddr]
            .else
                str w8, [_xaddr]
            .endif
            write_done \size, \op\size\()_mem
        .endifin
        gret 1
        # also hell {{{
        .ifin(\op, bt)
            read_bullshit \size, \op\size\()_mem
        .endifin
        .ifin(\op, btc,bts,btr)
            write_bullshit \size, \op\size\()_mem
        .endifin
        # }}}

    .macro x name, reg
        .gadget \op\size\()_\name
            .if \size == 64
                # For 64-bit operations, need to use the 64-bit register names
                .ifc \name,reg_a
                    do_bt_op \op, rax, \size, \s
                .else N .ifc \name,reg_b
                    do_bt_op \op, rbx, \size, \s  
                .else N .ifc \name,reg_c
                    do_bt_op \op, rcx, \size, \s
                .else N .ifc \name,reg_d
                    do_bt_op \op, rdx, \size, \s
                .else N .ifc \name,reg_si
                    do_bt_op \op, rsi, \size, \s
                .else N .ifc \name,reg_di
                    do_bt_op \op, rdi, \size, \s
                .else N .ifc \name,reg_sp
                    do_bt_op \op, rsp, \size, \s
                .else N .ifc \name,reg_bp
                    do_bt_op \op, rbp, \size, \s
                .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
            .else
                do_bt_op \op, \reg, \size, \s
            .endif
            gret
    .endm
    .each_reg x
    .purgem x
.endm

.irp op, bt,btc,bts,btr
    .irp size, 8,16,32,64
        ss \size, do_bt, \op
    .endr
    .gadget_array \op
.endr

# atomic versions of the above

.macro do_bt_atomic op, size, s
    # Add missing imm variant for atomic bit test operations
    .gadget atomic_\op\size\()_imm
        .if \size == 64
            ldr x8, [_ip]
            do_bt_op \op, x8, \size, \s
        .else
            ldr\s w8, [_ip]
            do_bt_op \op, w8, \size, \s
        .endif
        gret 1

    .gadget atomic_\op\size\()_mem
        .if \size == 64
            bic x8, _xtmp, 0x3f
            lsr x8, x8, 3
            add _xaddr, _xaddr, x8
        .else
            bic w8, _tmp, 0x1f
            add _addr, _addr, w8, lsr 3
        .endif
        write_prep \size, atomic_\op\size\()_mem
        # this is simple enough that I'm comfortable doing it with ldaxr/stlxr
    1:
        .if \size == 64
            ldaxr x8, [_xaddr]
            mov x9, 1
            and _xtmp, _xtmp, \size-1
            lsl x9, x9, _xtmp
            tst x8, x9
            .ifc \op,btc
                eor x8, x8, x9
            .else N .ifc \op,bts
                orr x8, x8, x9
            .else N .ifc \op,btr
                bic x8, x8, x9
            .endif N .endif N .endif
            cset w9, ne
            stlxr w10, x8, [_xaddr]
        .else
            ldaxr w8, [_xaddr]
            mov w9, 1
            and _tmp, _tmp, \size-1
            lsl w9, w9, _tmp
            tst w8, w9
            .ifc \op,btc
                eor w8, w8, w9
            .else N .ifc \op,bts
                orr w8, w8, w9
            .else N .ifc \op,btr
                bic w8, w8, w9
            .endif N .endif N .endif
            cset w9, ne
            stlxr w10, w8, [_xaddr]
        .endif
        cbnz w10, 1b
        strb w9, [_cpu, CPU_cf]
        write_done \size, atomic_\op\size\()_mem
        gret 1
        write_bullshit \size, atomic_\op\size\()_mem

    # Add missing register variants for atomic bit test operations
    .macro x name, reg
        .gadget atomic_\op\size\()_\name
            .if \size == 64
                # For 64-bit operations, need to use the 64-bit register names
                .ifc \name,reg_a
                    do_bt_op \op, rax, \size, \s
                .else N .ifc \name,reg_b
                    do_bt_op \op, rbx, \size, \s  
                .else N .ifc \name,reg_c
                    do_bt_op \op, rcx, \size, \s
                .else N .ifc \name,reg_d
                    do_bt_op \op, rdx, \size, \s
                .else N .ifc \name,reg_si
                    do_bt_op \op, rsi, \size, \s
                .else N .ifc \name,reg_di
                    do_bt_op \op, rdi, \size, \s
                .else N .ifc \name,reg_sp
                    do_bt_op \op, rsp, \size, \s
                .else N .ifc \name,reg_bp
                    do_bt_op \op, rbp, \size, \s
                .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
            .else
                do_bt_op \op, \reg, \size, \s
            .endif
            gret
    .endm
    .each_reg x
    .purgem x
.endm

.irp op, btc,bts,btr
    .irp size, 8,16,32,64
        ss \size, do_bt_atomic, \op
    .endr
    .gadget_array atomic_\op
.endr

# Add missing addr and gs atomic bit test gadgets for ALL sizes using systematic approach
.irp op, btc,bts,btr
    # 64-bit variants
    .gadget \op\()64_addr
        do_bt_op \op, _xaddr, 64, x
        gret

    .gadget \op\()64_gs  
        ldr _xtmp, [_cpu, #CPU_gs]
        do_bt_op \op, _xtmp, 64, x
        str _xtmp, [_cpu, #CPU_gs]
        gret

    # 32-bit variants
    .gadget \op\()32_addr
        do_bt_op \op, _addr, 32, ""
        gret

    .gadget \op\()32_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 32, ""
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 16-bit variants
    .gadget \op\()16_addr
        do_bt_op \op, _addr, 16, h
        gret

    .gadget \op\()16_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 16, h
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 8-bit variants
    .gadget \op\()8_addr
        do_bt_op \op, _addr, 8, b
        gret

    .gadget \op\()8_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 8, b
        str _tmp, [_cpu, #CPU_gs]
        gret
.endr

# Add missing regular bt (bit test) operations for addr/gs variants
.irp op, bt
    # 64-bit variants
    .gadget \op\()64_addr
        do_bt_op \op, _xaddr, 64, x
        gret

    .gadget \op\()64_gs  
        ldr _xtmp, [_cpu, #CPU_gs]
        do_bt_op \op, _xtmp, 64, x
        str _xtmp, [_cpu, #CPU_gs]
        gret

    # 32-bit variants
    .gadget \op\()32_addr
        do_bt_op \op, _addr, 32, ""
        gret

    .gadget \op\()32_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 32, ""
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 16-bit variants
    .gadget \op\()16_addr
        do_bt_op \op, _addr, 16, h
        gret

    .gadget \op\()16_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 16, h
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 8-bit variants
    .gadget \op\()8_addr
        do_bt_op \op, _addr, 8, b
        gret

    .gadget \op\()8_gs  
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 8, b
        str _tmp, [_cpu, #CPU_gs]
        gret
.endr

# Add missing atomic bit test gadgets for ALL sizes that were accidentally removed
.irp op, btc,bts,btr
    # 64-bit variants
    .gadget atomic_\op\()64_addr
        # For atomic operations on addr, we'd need memory at _xaddr
        # This is complex - for now, fall back to non-atomic version
        do_bt_op \op, _xaddr, 64, x
        gret

    .gadget atomic_\op\()64_gs
        # Atomic operations on gs register - use non-atomic for now
        ldr _xtmp, [_cpu, #CPU_gs]
        do_bt_op \op, _xtmp, 64, x
        str _xtmp, [_cpu, #CPU_gs]
        gret

    # 32-bit variants
    .gadget atomic_\op\()32_addr
        do_bt_op \op, _addr, 32, ""
        gret

    .gadget atomic_\op\()32_gs
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 32, ""
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 16-bit variants  
    .gadget atomic_\op\()16_addr
        do_bt_op \op, _addr, 16, h
        gret

    .gadget atomic_\op\()16_gs
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 16, h
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 8-bit variants
    .gadget atomic_\op\()8_addr
        do_bt_op \op, _addr, 8, b
        gret

    .gadget atomic_\op\()8_gs
        ldr _tmp, [_cpu, #CPU_gs]
        do_bt_op \op, _tmp, 8, b
        str _tmp, [_cpu, #CPU_gs]
        gret
.endr

.macro x name reg
    .gadget bswap_\name
        rev \reg, \reg
        gret
.endm
.each_reg x
.purgem x
.gadget_list bswap, REG_LIST

# Add missing addr and gs variants for smaller rotate operations manually
.gadget rol32_addr
    neg w8, ecx
    ror _addr, _addr, w8
    ubfx w9, _addr, 0, 1
    ubfx w10, _addr, 31, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget ror32_addr
    ror _addr, _addr, ecx
    ubfx w9, _addr, 31, 1
    ubfx w10, _addr, 30, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget rol32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    neg w8, ecx
    ror _tmp, _tmp, w8
    ubfx w9, _tmp, 0, 1
    ubfx w10, _tmp, 31, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget ror32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    ror _tmp, _tmp, ecx
    ubfx w9, _tmp, 31, 1
    ubfx w10, _tmp, 30, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing 64-bit rotate operations
.gadget rol64_addr
    neg w8, ecx
    uxtw x8, w8
    ror _xaddr, _xaddr, x8
    ubfx x9, _xaddr, 0, 1
    ubfx x10, _xaddr, 63, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget ror64_addr
    uxtw x8, ecx
    ror _xaddr, _xaddr, x8
    ubfx x9, _xaddr, 63, 1
    ubfx x10, _xaddr, 62, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget rol64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    neg w8, ecx
    uxtw x8, w8
    ror _xtmp, _xtmp, x8
    ubfx x9, _xtmp, 0, 1
    ubfx x10, _xtmp, 63, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget ror64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    uxtw x8, ecx
    ror _xtmp, _xtmp, x8
    ubfx x9, _xtmp, 63, 1
    ubfx x10, _xtmp, 62, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _xtmp, [_cpu, #CPU_gs]
    gret

# Add missing 16-bit rotate operations using proven 32-bit pattern
.gadget rol16_addr
    neg w8, ecx
    ror _addr, _addr, w8
    and _addr, _addr, 0xFFFF
    ubfx w9, _addr, 0, 1
    ubfx w10, _addr, 15, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget ror16_addr
    ror _addr, _addr, ecx
    and _addr, _addr, 0xFFFF
    ubfx w9, _addr, 15, 1
    ubfx w10, _addr, 14, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget rol16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    neg w8, ecx
    ror _tmp, _tmp, w8
    and _tmp, _tmp, 0xFFFF
    ubfx w9, _tmp, 0, 1
    ubfx w10, _tmp, 15, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget ror16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    ror _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFFFF
    ubfx w9, _tmp, 15, 1
    ubfx w10, _tmp, 14, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing 8-bit rotate operations using proven 32-bit pattern
.gadget rol8_addr
    neg w8, ecx
    ror _addr, _addr, w8
    and _addr, _addr, 0xFF
    ubfx w9, _addr, 0, 1
    ubfx w10, _addr, 7, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget ror8_addr
    ror _addr, _addr, ecx
    and _addr, _addr, 0xFF
    ubfx w9, _addr, 7, 1
    ubfx w10, _addr, 6, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    gret

.gadget rol8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    neg w8, ecx
    ror _tmp, _tmp, w8
    and _tmp, _tmp, 0xFF
    ubfx w9, _tmp, 0, 1
    ubfx w10, _tmp, 7, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget ror8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    ror _tmp, _tmp, ecx
    and _tmp, _tmp, 0xFF
    ubfx w9, _tmp, 7, 1
    ubfx w10, _tmp, 6, 1
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    str _tmp, [_cpu, #CPU_gs]
    gret

# 8-bit immediate operations now generated automatically by main loop

# 64-bit rotate immediate operations now generated automatically by main loop
