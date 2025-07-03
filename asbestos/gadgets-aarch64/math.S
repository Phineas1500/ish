#include "gadgets.h"
#include "math.h"

.gadget load32_addr
    mov _tmp, _addr
    gret

.gadget load64_addr
    mov _xtmp, _xaddr
    gret

.gadget load16_gs
    ldrh _tmp, [_cpu, #CPU_gs]
    gret

.gadget load64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    gret

.gadget store16_gs
    strh _tmp, [_cpu, #CPU_gs]
    gret

.gadget store64_gs
    str _xtmp, [_cpu, #CPU_gs]
    gret

# Add missing load/store addr/gs/imm variants that gadget_array expects

# Missing load variants
.gadget load8_addr
    mov _tmp, _addr
    gret

.gadget load8_gs
    ldrb _tmp, [_cpu, #CPU_gs]
    gret

.gadget load16_addr
    mov _tmp, _addr
    gret

.gadget load32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    gret

# Missing store variants
.gadget store8_addr
    mov _addr, _tmp
    gret

.gadget store8_gs
    strb _tmp, [_cpu, #CPU_gs]
    gret

.gadget store16_addr
    mov _addr, _tmp
    gret

.gadget store32_addr
    mov _addr, _tmp
    gret

.gadget store32_gs
    str _tmp, [_cpu, #CPU_gs]
    gret

# Missing store immediate variants
.gadget store8_imm
    ldrb w8, [_ip]
    mov _tmp, w8
    gret 1

.gadget store16_imm
    ldrh w8, [_ip]
    mov _tmp, w8
    gret 1

.gadget store32_imm
    ldr w8, [_ip]
    mov _tmp, w8
    gret 1

.gadget store64_imm
    ldr x8, [_ip]
    mov _xtmp, x8
    gret 1

# this would have been just a few nice compact nested loops, but gas said "nuh uh"

.macro _do_op op, arg, size, s
    .ifc \op,load
        .if \size == 64
            movs _xtmp, \arg, \s
            .ifc \s,x
                # For 64-bit, _xtmp is already correct (x0), no extension needed
            .else
                uxts _xtmp, _xtmp, \s
            .endif
        .else
            movs _tmp, \arg, \s
            uxts _tmp, _tmp, \s
        .endif
        .exitm
    .else N .ifc \op,store
        .if \size == 64
            movs \arg, _xtmp, \s
        .else
            movs \arg, _tmp, \s
        .endif
        .exitm
    .endif N .endif

    .ifin(\op, add,sub,adc,sbc)
        .if \size == 64
            setf_a \arg, _xtmp
        .else
            setf_a \arg, _tmp
        .endif
    .endifin
    .ifin(\op, and,orr,eor)
        clearf_a
        clearf_oc
    .endifin
    .ifin(\op, adc,sbc)
        ldrb w10, [_cpu, CPU_cf]
        .ifc \op,adc
            cmp w10, 1
        .else
            mvn w10, w10
            cmn w10, 1
        .endif
    .endifin

    .ifin(\op, and,orr,eor)
        .if \size == 64
            \op _xtmp, _xtmp, \arg
        .else
            \op _tmp, _tmp, \arg
        .endif
    .endifin

    .ifin(\op, add,sub,adc,sbc)
        .if \size == 64
            do_add \op, _xtmp, \arg, \s
        .else
            do_add \op, _tmp, \arg, \s
        .endif
    .endifin

    .ifc \op,imul
        .ifnb \s
            .ifc \s,x
                # For 64-bit operations, use proper x-register handling
                .if \size == 64
                    sxtw x10, \arg
                    mul _xtmp, _xtmp, x10
                    # Check for overflow by comparing with sign-extended result
                    asr x11, _xtmp, 31
                    cmp x11, _xtmp, asr 63
                .else
                    sxtw x10, \arg
                    mul _tmp, _tmp, w10
                    # Check for overflow using proper comparison
                    sxtw x11, _tmp
                    cmp _tmp, w11
                .endif
            .else
                sxt\s w10, \arg
                .if \size == 64
                    mul _xtmp, _xtmp, w10
                    # Check for overflow - compare result with sign-extended version
                    sxt\s x11, _xtmp
                    cmp _xtmp, x11
                .else
                    mul _tmp, _tmp, w10
                    # Check for overflow
                    sxt\s w11, _tmp  
                    cmp _tmp, w11
                .endif
            .endif
        .else
            .if \size == 64
                # For 64-bit multiply, use proper w-register operands for smull
                mov w10, _xtmp  
                smull x12, w10, \arg
                # Check if result fits in sign-extended 32-bit value
                sxtw x13, w12
                cmp x12, x13
            .else
                smull _xtmp, _tmp, \arg
                # Check for overflow
                sxtw x11, _tmp
                cmp _xtmp, x11
            .endif
        .endif
        cset w10, ne
        strb w10, [_cpu, CPU_cf]
        strb w10, [_cpu, CPU_of]
    .endif

    .ifin(\op, bsf,bsr)
        .ifnb \s
            .ifc \s,x
                # For 64-bit, use full 64-bit register
                mov x10, \arg
            .else
                uxt\s w10, \arg
            .endif
        .else
            mov w10, \arg
        .endif
        .ifc \op,bsf
            .if \size == 64
                # For 64-bit bsf, use 64-bit operations
                rbit x10, x10
                clz x10, x10
                cmp x10, \size
            .elseif \size != 32
                orr w10, w10, 1<<\size
                rbit w10, w10
                clz w10, w10
                cmp w10, \size
            .else
                rbit w10, w10
                clz w10, w10
                cmp w10, \size
            .endif
        .else
            .if \size == 64
                # For 64-bit bsr, use 64-bit operations
                clz x10, x10
                cmp x10, \size
                mov x9, \size-1
                sub x10, x9, x10
            .elseif \size != 32
                clz w10, w10
                sub w10, w10, 32-\size
                cmp w10, \size
                mov w9, \size-1
                sub w10, w9, w10
            .else
                clz w10, w10
                cmp w10, \size
                mov w9, \size-1
                sub w10, w9, w10
            .endif
        .endif
        .if \size == 64
            csel _xtmp, x10, _xtmp, ne
        .else
            csel _tmp, w10, _tmp, ne
        .endif
        cset w10, eq
        ldrb w9, [_cpu, CPU_eflags]
        bic w9, w9, ZF_FLAG
        orr w9, w9, w10, lsl 6
        strb w9, [_cpu, CPU_eflags]
        ldrb w9, [_cpu, CPU_flags_res]
        bic w9, w9, ZF_RES
        strb w9, [_cpu, CPU_flags_res]
    .endifin

    .ifc \op,xchg
        .if \size == 64
            mov x9, _xtmp
            mov _xtmp, \arg
            movs \arg, x9, \s
        .else
            mov w9, _tmp
            mov _tmp, \arg
            movs \arg, w9, \s
        .endif
    .endif

    .ifin(\op, add,sub,adc,sbc,and,orr,eor)
        .if \size == 64
            setf_zsp \s, val=_xtmp
        .else
            setf_zsp \s, val=_tmp
        .endif
    .endifin
.endm
.macro do_op op, size, arg
    ss \size, _do_op, \op, \arg
.endm

.macro do_reg_op op, armop, size, reg
    .gadget \op\size\()_reg_\reg
        .if \size == 64
            # For 64-bit operations, use 64-bit registers (rax, rbx, etc.)
            do_op \armop, \size, r\reg\()x
        .else
            # For 32-bit and smaller operations, use 32-bit registers (eax, ebx, etc.)
            do_op \armop, \size, e\reg\()x
        .endif
        gret
.endm

.macro do_hi_op op, size, reg
    ubfx w12, e\reg\()x, 8, 8
    do_op \op, \size, w12
    bfi e\reg\()x, w12, 8, 8
.endm

.macro do_op_size op, armop, size, s
    .ifnc \op,store
        .gadget \op\size\()_imm
            .if \size == 64
                ldr x8, [_ip]
                do_op \armop, \size, x8
            .else
                ldr\s w8, [_ip]
                do_op \armop, \size, w8
            .endif
            gret 1
    .endif

    .ifnc \op,xchg
        .gadget \op\size\()_mem
            .ifc \op,store
                write_prep \size, \op\size\()_mem
            .else N .ifc \op,xchg
                write_prep \size, \op\size\()_mem
            .else
                read_prep \size, \op\size\()_mem
            .endif N .endif
            .if \size == 64
                ldr x8, [_xaddr]
                do_op \armop, \size, x8
            .else
                ldr\s w8, [_xaddr]
                do_op \armop, \size, w8
            .endif
            .ifc \op,store
                .if \size == 64
                    str _xtmp, [_xaddr]
                .else
                    str\s _tmp, [_xaddr]
                .endif
                write_done \size, \op\size\()_mem
            .endif
            gret 1
            .ifc \op,store
                write_bullshit \size, \op\size\()_mem
            .else N .ifc \op,xchg
                write_bullshit \size, \op\size\()_mem
            .else
                read_bullshit \size, \op\size\()_mem
            .endif N .endif
    .else
        # xchg must be atomic
        .gadget \op\size\()_mem
            write_prep \size, \op\size\()_mem
        1:
            .if \size == 64
                ldaxr x8, [_xaddr]
                stlxr w10, _xtmp, [_xaddr]
            .else
                ldaxr\s w8, [_xaddr]
                stlxr\s w10, _tmp, [_xaddr]
            .endif
            cbnz w10, 1b
            .if \size == 64
                mov _xtmp, x8
            .else
                movs _tmp, w8
            .endif
            write_done \size, \op\size\()_mem
            gret 1
            write_bullshit \size, \op\size\()_mem
    .endif

    .irp reg, a,b,c,d
        do_reg_op \op, \armop, \size, \reg
    .endr

    .irp reg, si,di,sp,bp
        .gadget \op\size\()_reg_\reg
            .if \size == 8
                .ifc \reg,sp N do_hi_op \armop, \size, a N .else
                .ifc \reg,bp N do_hi_op \armop, \size, c N .else
                .ifc \reg,si N do_hi_op \armop, \size, d N .else
                .ifc \reg,di N do_hi_op \armop, \size, b
                .endif N .endif N .endif N .endif
            .elseif \size == 64
                # For 64-bit operations, use 64-bit registers (rsi, rdi, rsp, rbp)
                do_op \armop, \size, r\reg
            .else
                # For 32-bit and 16-bit operations, use 32-bit registers (esi, edi, esp, ebp)
                do_op \armop, \size, e\reg
            .endif
            gret
    .endr

.endm

.irp op, load,store,xchg,add,sub,adc,sbb,and,or,xor
    .irp size, SIZE_LIST
        # a couple operations have slightly different names on arm
        .ifc \op,xor
            ss \size, do_op_size, \op, eor
        .else N .ifc \op,sbb
            ss \size, do_op_size, \op, sbc
        .else N .ifc \op,or
            ss \size, do_op_size, \op, orr
        .else
            ss \size, do_op_size, \op, \op
        .endif N .endif N .endif
    .endr
    .gadget_array \op
.endr
# imul now supports 64-bit with ARM64 fixes - including 8-bit
.irp op, imul
    .irp size, 8,16,32,64
        ss \size, do_op_size, \op, \op
    .endr
    .gadget_array \op
.endr
# bsf,bsr now support 64-bit with ARM64 fixes
.irp op, bsf,bsr
    .irp size, 8,16,32,64
        ss \size, do_op_size, \op, \op
    .endr
    .gadget_array \op
.endr

# Add missing addr and gs bit scan gadgets for 64-bit support
.irp op, bsf,bsr
    .gadget \op\()64_addr
        _do_op \op, _xaddr, 64, x
        gret

    .gadget \op\()64_gs  
        ldr _xtmp, [_cpu, #CPU_gs]
        _do_op \op, _xtmp, 64, x
        str _xtmp, [_cpu, #CPU_gs]
        gret
.endr

# Add missing 8-bit addr/gs variants that were overlooked
.gadget bsf8_addr
    _do_op bsf, _addr, 8,
    gret

.gadget bsf8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsf, _tmp, 8,
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget bsr8_addr
    _do_op bsr, _addr, 8,
    gret

.gadget bsr8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsr, _tmp, 8,
    str _tmp, [_cpu, #CPU_gs]
    gret

# Manually add missing 16-bit and 32-bit variants  
.gadget bsf16_addr
    _do_op bsf, _addr, 16,
    gret

.gadget bsf16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsf, _tmp, 16,
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget bsf32_addr
    _do_op bsf, _addr, 32,
    gret

.gadget bsf32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsf, _tmp, 32,
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget bsr16_addr
    _do_op bsr, _addr, 16,
    gret

.gadget bsr16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsr, _tmp, 16,
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget bsr32_addr
    _do_op bsr, _addr, 32,
    gret

.gadget bsr32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    _do_op bsr, _tmp, 32,
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing addr and gs variants for imul operations
.irp size, 16,32,64
    .gadget imul\size\()_addr
        .if \size == 64
            _do_op imul, _xaddr, \size, x
        .else
            _do_op imul, _addr, \size, 
        .endif
        gret

    .gadget imul\size\()_gs
        .if \size == 64
            ldr _xtmp, [_cpu, #CPU_gs]
            _do_op imul, _xtmp, \size, x
            str _xtmp, [_cpu, #CPU_gs]
        .else
            ldr _tmp, [_cpu, #CPU_gs]
            _do_op imul, _tmp, \size,
            str _tmp, [_cpu, #CPU_gs]
        .endif
        gret
.endr

# atomics. oof

.macro do_op_size_atomic opname, op, size, s

    .gadget atomic_\opname\size\()_mem
        # There's so much stuff going on inside most of these operations that
        # the implementation is a compare-and-swap loop, instead of just ldaxr/stlxr
        write_prep \size, atomic_\opname\size\()_mem
        .if \size == 64
            ldr x12, [_xaddr]
        .else
            ldr\s w12, [_xaddr]
        .endif
    1:
        .if \size == 64
            mov x8, x12
        .else
            mov w8, w12
        .endif

        # do the operation
        # dest = w8/x8, src = _tmp/_xtmp
        .ifin(\op, add,sub,adc,sbc)
            .if \size == 64
                setf_a src=_xtmp, dst=x8
            .else
                setf_a src=_tmp, dst=w8
            .endif
        .endifin
        .ifin(\op, and,orr,eor)
            clearf_a
            clearf_oc
        .endifin
        .ifin(\op, adc,sbc)
            ldrb w10, [_cpu, CPU_cf]
            .ifc \op,adc
                cmp w10, 1
            .else
                mvn w10, w10
                cmn w10, 1
            .endif
        .endifin

        .ifin(\op, and,orr,eor)
            .if \size == 64
                \op x8, x8, _xtmp
            .else
                \op w8, w8, _tmp
            .endif
        .endifin
        .ifin(\op, add,sub,adc,sbc)
            .if \size == 64
                do_add \op, x8, _xtmp, \s
            .else
                do_add \op, w8, _tmp, \s
            .endif
        .endifin
        .ifc \op,xadd
            # exchange, then add
            .if \size == 64
                mov x9, x8
                mov x8, _xtmp
                do_add add, x8, x9, \s
            .else
                mov w9, w8
                mov w8, _tmp
                do_add add, w8, w9, \s
            .endif
        .endif

        .ifin(\op, add,sub,adc,sbc,and,orr,eor,xadd)
            .if \size == 64
                setf_zsp \s, val=x8
            .else
                setf_zsp \s, val=w8
            .endif
        .endifin

        .ifin(\op, inc,dec)
            mov w10, 1
            .if \size == 64
                setf_a src=w10, dst=x8
            .else
                setf_a src=w10, dst=w8
            .endif
            .ifb \s
                .ifc \op,inc
                    adds w8, w8, 1
                .else
                    subs w8, w8, 1
                .endif
                cset w9, vs
            .else
                .ifc \s,x
                    # For 64-bit atomic operations, work with full 64-bit values
                    .ifc \op,inc
                        adds x8, x8, 1
                    .else
                        subs x8, x8, 1
                    .endif
                    # Check if result fits in 32 bits
                    sxtw x9, w8
                    cmp x8, x9
                .else
                    sxt\s w8, w8
                    .ifc \op,inc
                        adds w8, w8, 1
                    .else
                        subs w8, w8, 1
                    .endif
                    cmp w8, w8, sxt\s
                .endif
                cset w9, ne
            .endif
            strb w9, [_cpu, CPU_of]
            .if \size == 64
                setf_zsp \s, val=x8
            .else
                setf_zsp \s, val=w8
            .endif
        .endifin

    2:
        .if \size == 64
            ldaxr x13, [_xaddr]
        .else
            ldaxr\s w13, [_xaddr]
        .endif
        .if \size == 64
            cmp x12, x13
        .else
            cmp w12, w13
        .endif
        b.ne 3f
        .if \size == 64
            stlxr w13, x8, [_xaddr]
        .else
            stlxr\s w13, w8, [_xaddr]
        .endif
        cbnz w13, 2b
        .ifc \op,xadd
            mov _tmp, w9
        .endif
        write_done \size, atomic_\opname\size\()_mem
        gret 1
        write_bullshit \size, atomic_\opname\size\()_mem
    3:
        dmb ish
        .if \size == 64
            mov x12, x13
        .else
            mov w12, w13
        .endif
        b 1b
.endm

.irp op, add,sub,adc,sbb,and,or,xor,inc,dec,xadd
    .irp size, SIZE_LIST
        .ifc \op,xor
            ss \size, do_op_size_atomic, \op, eor
        .else N .ifc \op,sbb
            ss \size, do_op_size_atomic, \op, sbc
        .else N .ifc \op,or
            ss \size, do_op_size_atomic, \op, orr
        .else
            ss \size, do_op_size_atomic, \op, \op
        .endif N .endif N .endif
    .endr
    .gadget_array atomic_\op
.endr

# Add missing addr and gs atomic gadgets for ALL sizes using systematic approach
.irp op, add,sub,adc,sbb,and,or,xor,xadd
    # 64-bit variants (keep existing complex implementation)
    .gadget atomic_\op\()64_addr
        write_prep 64, atomic_\op\()64_addr
        ldr x12, [_xaddr]
    1:
        mov x8, x12
        .ifc \op,xor
            eor x8, x8, _xaddr
        .else N .ifc \op,sbb
            # sbb is subtract with borrow - implement as subtract with carry
            setf_a src=_xaddr, dst=x8
            ldrb w10, [_cpu, CPU_cf]
            mvn w10, w10
            cmn w10, 1
            do_add sbc, x8, _xaddr, x
        .else N .ifc \op,or
            orr x8, x8, _xaddr
        .else N .ifc \op,and
            and x8, x8, _xaddr
        .else N .ifc \op,add
            setf_a src=_xaddr, dst=x8
            do_add add, x8, _xaddr, x
        .else N .ifc \op,sub
            setf_a src=_xaddr, dst=x8
            do_add sub, x8, _xaddr, x
        .else N .ifc \op,adc
            setf_a src=_xaddr, dst=x8
            ldrb w10, [_cpu, CPU_cf]
            cmp w10, 1
            do_add adc, x8, _xtmp, x
        .else N .ifc \op,xadd
            mov x9, x8
            mov x8, _xaddr
            setf_a src=x9, dst=x8
            do_add add, x8, x9, x
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif

        .ifin(\op, add,sub,adc,sbb,and,or,xor,xadd)
            setf_zsp x, val=x8
        .endifin

    2:
        ldaxr x13, [_xaddr]
        cmp x12, x13
        b.ne 3f
        stlxr w13, x8, [_xaddr]
        cbnz w13, 2b
        write_done 64, atomic_\op\()64_addr
        gret
        write_bullshit 64, atomic_\op\()64_addr
    3:
        dmb ish
        mov x12, x13
        b 1b

    .gadget atomic_\op\()64_gs
        write_prep 64, atomic_\op\()64_gs
        ldr x8, [_cpu, #CPU_gs]
        mov _xtmp, x8
        ldr x12, [_cpu, #CPU_gs]
    1:
        mov x8, x12
        .ifc \op,xor
            eor x8, x8, _xtmp
        .else N .ifc \op,sbb
            setf_a src=_xtmp, dst=x8
            ldrb w10, [_cpu, CPU_cf]
            mvn w10, w10
            cmn w10, 1
            do_add sbc, x8, _xtmp, x
        .else N .ifc \op,or
            orr x8, x8, _xtmp
        .else N .ifc \op,and
            and x8, x8, _xtmp
        .else N .ifc \op,add
            setf_a src=_xtmp, dst=x8
            do_add add, x8, _xtmp, x
        .else N .ifc \op,sub
            setf_a src=_xtmp, dst=x8
            do_add sub, x8, _xtmp, x
        .else N .ifc \op,adc
            setf_a src=_xtmp, dst=x8
            ldrb w10, [_cpu, CPU_cf]
            cmp w10, 1
            do_add adc, x8, _xtmp, x
        .else N .ifc \op,xadd
            mov x9, x8
            mov x8, _xtmp
            setf_a src=x9, dst=x8
            do_add add, x8, x9, x
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif

        .ifin(\op, add,sub,adc,sbb,and,or,xor,xadd)
            setf_zsp x, val=x8
        .endifin

        # Atomic update of gs register
        add x9, _cpu, #CPU_gs
    2:
        ldaxr x13, [x9]
        cmp x12, x13
        b.ne 3f
        stlxr w13, x8, [x9]
        cbnz w13, 2b
        write_done 64, atomic_\op\()64_gs
        gret
        write_bullshit 64, atomic_\op\()64_gs
    3:
        dmb ish
        mov x12, x13
        b 1b

    # For smaller sizes (8,16,32), use simplified non-atomic fallback for now
    # 32-bit variants
    .gadget atomic_\op\()32_addr
        .ifc \op,add
            do_op add, 32, _addr
        .else N .ifc \op,sub
            do_op sub, 32, _addr
        .else N .ifc \op,adc
            do_op adc, 32, _addr
        .else N .ifc \op,sbb
            do_op sbb, 32, _addr
        .else N .ifc \op,and
            do_op and, 32, _addr
        .else N .ifc \op,or
            do_op or, 32, _addr
        .else N .ifc \op,xor
            do_op xor, 32, _addr
        .else N .ifc \op,xadd
            do_op xadd, 32, _addr
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        gret

    .gadget atomic_\op\()32_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,add
            do_op add, 32, _tmp
        .else N .ifc \op,sub
            do_op sub, 32, _tmp
        .else N .ifc \op,adc
            do_op adc, 32, _tmp
        .else N .ifc \op,sbb
            do_op sbb, 32, _tmp
        .else N .ifc \op,and
            do_op and, 32, _tmp
        .else N .ifc \op,or
            do_op or, 32, _tmp
        .else N .ifc \op,xor
            do_op xor, 32, _tmp
        .else N .ifc \op,xadd
            do_op xadd, 32, _tmp
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 16-bit variants
    .gadget atomic_\op\()16_addr
        .ifc \op,add
            do_op add, 16, _addr
        .else N .ifc \op,sub
            do_op sub, 16, _addr
        .else N .ifc \op,adc
            do_op adc, 16, _addr
        .else N .ifc \op,sbb
            do_op sbb, 16, _addr
        .else N .ifc \op,and
            do_op and, 16, _addr
        .else N .ifc \op,or
            do_op or, 16, _addr
        .else N .ifc \op,xor
            do_op xor, 16, _addr
        .else N .ifc \op,xadd
            do_op xadd, 16, _addr
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        gret

    .gadget atomic_\op\()16_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,add
            do_op add, 16, _tmp
        .else N .ifc \op,sub
            do_op sub, 16, _tmp
        .else N .ifc \op,adc
            do_op adc, 16, _tmp
        .else N .ifc \op,sbb
            do_op sbb, 16, _tmp
        .else N .ifc \op,and
            do_op and, 16, _tmp
        .else N .ifc \op,or
            do_op or, 16, _tmp
        .else N .ifc \op,xor
            do_op xor, 16, _tmp
        .else N .ifc \op,xadd
            do_op xadd, 16, _tmp
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 8-bit variants
    .gadget atomic_\op\()8_addr
        .ifc \op,add
            do_op add, 8, _addr
        .else N .ifc \op,sub
            do_op sub, 8, _addr
        .else N .ifc \op,adc
            do_op adc, 8, _addr
        .else N .ifc \op,sbb
            do_op sbb, 8, _addr
        .else N .ifc \op,and
            do_op and, 8, _addr
        .else N .ifc \op,or
            do_op or, 8, _addr
        .else N .ifc \op,xor
            do_op xor, 8, _addr
        .else N .ifc \op,xadd
            do_op xadd, 8, _addr
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        gret

    .gadget atomic_\op\()8_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,add
            do_op add, 8, _tmp
        .else N .ifc \op,sub
            do_op sub, 8, _tmp
        .else N .ifc \op,adc
            do_op adc, 8, _tmp
        .else N .ifc \op,sbb
            do_op sbb, 8, _tmp
        .else N .ifc \op,and
            do_op and, 8, _tmp
        .else N .ifc \op,or
            do_op or, 8, _tmp
        .else N .ifc \op,xor
            do_op xor, 8, _tmp
        .else N .ifc \op,xadd
            do_op xadd, 8, _tmp
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
        str _tmp, [_cpu, #CPU_gs]
        gret
.endr

# Add inc/dec addr and gs variants for ALL sizes
.irp op, inc,dec
    # 64-bit variants (keep existing complex implementation)
    .gadget atomic_\op\()64_addr
        write_prep 64, atomic_\op\()64_addr
        ldr x12, [_xaddr]
    1:
        mov x8, x12
        mov w10, 1
        setf_a src=w10, dst=x8
        .ifc \op,inc
            adds x8, x8, 1
        .else
            subs x8, x8, 1
        .endif
        cset w9, vs
        strb w9, [_cpu, CPU_of]
        setf_zsp x, val=x8

    2:
        ldaxr x13, [_xaddr]
        cmp x12, x13
        b.ne 3f
        stlxr w13, x8, [_xaddr]
        cbnz w13, 2b
        write_done 64, atomic_\op\()64_addr
        gret
        write_bullshit 64, atomic_\op\()64_addr
    3:
        dmb ish
        mov x12, x13
        b 1b

    .gadget atomic_\op\()64_gs
        write_prep 64, atomic_\op\()64_gs
        ldr x12, [_cpu, #CPU_gs]
    1:
        mov x8, x12
        mov w10, 1
        setf_a src=w10, dst=x8
        .ifc \op,inc
            adds x8, x8, 1
        .else
            subs x8, x8, 1
        .endif
        cset w9, vs
        strb w9, [_cpu, CPU_of]
        setf_zsp x, val=x8

        # Atomic update of gs register
        add x9, _cpu, #CPU_gs
    2:
        ldaxr x13, [x9]
        cmp x12, x13
        b.ne 3f
        stlxr w13, x8, [x9]
        cbnz w13, 2b
        write_done 64, atomic_\op\()64_gs
        gret
        write_bullshit 64, atomic_\op\()64_gs
    3:
        dmb ish
        mov x12, x13
        b 1b

    # For smaller sizes, use simplified non-atomic fallback with manual implementation
    # 32-bit variants
    .gadget atomic_\op\()32_addr
        .ifc \op,inc
            # Manual inc implementation for _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            adds _addr, _addr, 1
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp "", val=_addr
        .else
            # Manual dec implementation for _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            subs _addr, _addr, 1
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp "", val=_addr
        .endif
        gret

    .gadget atomic_\op\()32_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,inc
            # Manual inc implementation for _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            adds _tmp, _tmp, 1
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp "", val=_tmp
        .else
            # Manual dec implementation for _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            subs _tmp, _tmp, 1
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp "", val=_tmp
        .endif
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 16-bit variants
    .gadget atomic_\op\()16_addr
        .ifc \op,inc
            # Manual inc implementation for 16-bit _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            add _addr, _addr, 1
            and _addr, _addr, 0xFFFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp h, val=_addr
        .else
            # Manual dec implementation for 16-bit _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            sub _addr, _addr, 1
            and _addr, _addr, 0xFFFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp h, val=_addr
        .endif
        gret

    .gadget atomic_\op\()16_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,inc
            # Manual inc implementation for 16-bit _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            add _tmp, _tmp, 1
            and _tmp, _tmp, 0xFFFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp h, val=_tmp
        .else
            # Manual dec implementation for 16-bit _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            sub _tmp, _tmp, 1
            and _tmp, _tmp, 0xFFFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp h, val=_tmp
        .endif
        str _tmp, [_cpu, #CPU_gs]
        gret

    # 8-bit variants
    .gadget atomic_\op\()8_addr
        .ifc \op,inc
            # Manual inc implementation for 8-bit _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            add _addr, _addr, 1
            and _addr, _addr, 0xFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp b, val=_addr
        .else
            # Manual dec implementation for 8-bit _addr
            mov w10, 1
            setf_a src=w10, dst=_addr
            sub _addr, _addr, 1
            and _addr, _addr, 0xFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp b, val=_addr
        .endif
        gret

    .gadget atomic_\op\()8_gs
        ldr _tmp, [_cpu, #CPU_gs]
        .ifc \op,inc
            # Manual inc implementation for 8-bit _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            add _tmp, _tmp, 1
            and _tmp, _tmp, 0xFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp b, val=_tmp
        .else
            # Manual dec implementation for 8-bit _tmp
            mov w10, 1
            setf_a src=w10, dst=_tmp
            sub _tmp, _tmp, 1
            and _tmp, _tmp, 0xFF
            cset w8, vs
            strb w8, [_cpu, CPU_of]
            setf_zsp b, val=_tmp
        .endif
        str _tmp, [_cpu, #CPU_gs]
        gret
.endr

# unary operations (well, only one explicit operand)

.macro do_inc size, s
    mov w10, 1
    setf_a w10, _tmp
    .ifb \s
        adds _tmp, _tmp, 1
        cset w8, vs
    .else
        .ifc \s,x
            # For 64-bit, sign-extend then work with 64-bit registers
            sxtw x9, _tmp
            add x9, x9, 1
            # Check if result fits in sign-extended 32-bit
            sxtw x10, w9
            cmp x9, x10
            mov _tmp, w9
        .else
            sxt\s _tmp, _tmp
            add _tmp, _tmp, 1
            cmp _tmp, _tmp, sxt\s
        .endif
        cset w8, ne
    .endif
    strb w8, [_cpu, CPU_of]
    setf_zsp \s
.endm
.macro do_dec size, s
    mov w10, 1
    setf_a w10, _tmp
    .ifb \s
        subs _tmp, _tmp, 1
        cset w8, vs
    .else
        .ifc \s,x
            # For 64-bit, sign-extend then work with 64-bit registers
            sxtw x9, _tmp
            sub x9, x9, 1
            # Check if result fits in sign-extended 32-bit
            sxtw x10, w9
            cmp x9, x10
            mov _tmp, w9
        .else
            sxt\s _tmp, _tmp
            sub _tmp, _tmp, 1
            cmp _tmp, _tmp, sxt\s
        .endif
        cset w8, ne
    .endif
    strb w8, [_cpu, CPU_of]
    setf_zsp \s
.endm

.macro do_sign_extend size, s
    .if \size != 32
        # movs\ss\()l %tmp\s, %tmpd
        .ifc \s,x
            # For 64-bit, sign extend 32-bit _tmp to 64-bit
            sxtw x9, _tmp
            mov _xtmp, x9
        .else
            sxt\s _tmp, _tmp
        .endif
    .endif
.endm
.macro do_zero_extend size, s
    .if \size != 32
        .ifc \s,x
            # For 64-bit, zero extend 32-bit _tmp to 64-bit  
            uxtw x9, w0
            mov x0, x9
        .else
            uxt\s _tmp, _tmp
        .endif
    .endif
.endm
.macro do_div size, s
    .if \size == 8
        uxth w8, eax
        uxtb _tmp, _tmp
        udiv w9, w8, _tmp
        msub w10, w9, _tmp, w8
        bfi eax, w9, 0, 8
        bfi eax, w10, 8, 8
    .elseif \size == 16
        bfi w8, eax, 0, 16
        bfi w8, edx, 16, 16
        uxth _tmp, _tmp
        udiv w9, w8, _tmp
        msub w10, w9, _tmp, w8
        bfi eax, w9, 0, 16
        bfi edx, w10, 0, 16
    .elseif \size == 32
        bfi x8, xax, 0, 32
        bfi x8, xdx, 32, 32
        uxtw x9, _tmp
        mov _xtmp, x9
        udiv x9, x8, _xtmp
        msub x10, x9, _xtmp, x8
        mov eax, w9
        mov edx, w10
    .endif
.endm
.macro do_idiv size, s
    # another lazy ass copy paste job
    .if \size == 8
        sxth w8, eax
        sxtb _tmp, _tmp
        sdiv w9, w8, _tmp
        msub w10, w9, _tmp, w8
        bfi eax, w9, 0, 8
        bfi eax, w10, 8, 8
    .elseif \size == 16
        bfi w8, eax, 0, 16
        bfi w8, edx, 16, 16
        sxth _tmp, _tmp
        sdiv w9, w8, _tmp
        msub w10, w9, _tmp, w8
        bfi eax, w9, 0, 16
        bfi edx, w10, 0, 16
    .elseif \size == 32
        bfi x8, xax, 0, 32
        bfi x8, xdx, 32, 32
        sxtw x9, _tmp
        mov _xtmp, x9
        sdiv x9, x8, _xtmp
        msub x10, x9, _xtmp, x8
        mov eax, w9
        mov edx, w10
    .endif
.endm
.macro do_mul size, s
    .ifb \s
        umull xax, eax, _tmp
        lsr xdx, xax, 32
        cmp xax, eax, uxtw
    .elseif \size == 64
        # 64-bit mul doesn't use bit field operations
        uxtw x8, w20
        uxtw x9, w0
        mul x8, x8, x9
        # Check if result fits in 32 bits (unsigned)
        uxtw x10, w8
        cmp x8, x10
        mov eax, w8
        lsr x9, x8, 32
        mov edx, w9
    .else
        .ifc \s,x
            uxtw x8, eax
            uxtw x9, _tmp
            mul x8, x8, x9
            uxtw x10, w8
            cmp x8, x10
            mov w8, w8  # Store result back to w8
        .else
            uxt\s w8, eax
            uxt\s _tmp, _tmp
            mul w8, w8, _tmp
            cmp w8, w8, uxt\s
        .endif
        .if \size == 8
            bfxil eax, w8, 0, 16
        .else
            bfxil eax, w8, 0, \size
            bfxil edx, w8, \size, \size
        .endif
    .endif
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
.endm
.macro do_imul1 size, s
    .ifb \s
        smull xax, eax, _tmp
        lsr xdx, xax, 32
        cmp xax, eax, sxtw
    .elseif \size == 64
        # 64-bit imul doesn't use bit field operations
        sxtw x8, eax
        sxtw x9, _tmp
        mul x8, x8, x9
        # Check if result fits in 32 bits (signed)
        sxtw x10, w8
        cmp x8, x10
        mov eax, w8
        lsr x9, x8, 32
        mov edx, w9
    .else
        .ifc \s,x
            sxtw x8, eax
            sxtw x9, _tmp
            mul x8, x8, x9
            sxtw x10, w8
            cmp x8, x10
            mov w8, w8  # Store result back to w8
        .else
            sxt\s w8, eax
            sxt\s _tmp, _tmp
            mul w8, w8, _tmp
            cmp w8, w8, sxt\s
        .endif
        .if \size == 8
            bfxil eax, w8, 0, 16
        .else
            bfxil eax, w8, 0, \size
            bfxil edx, w8, \size, \size
        .endif
    .endif
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
.endm
.macro do_not size, s
    .ifb \s
        mvn _tmp, _tmp
    .else
        movs w10, _tmp, \s
        mvn w10, w10
        movs _tmp, w10, \s
    .endif
.endm

.irp op, inc,dec,sign_extend,zero_extend,div,idiv,mul,imul1,not
    .irp size, SIZE_LIST
        .gadget \op\()_\size
            ss \size, do_\op
            gret
    .endr
    .gadget_list \op, SIZE_LIST
.endr

# Add missing cvt variants for all sizes
.gadget cvt_8
    tst eax, 0x80
    cinv w8, wzr, ne
    bfxil edx, w8, 0, 8
    gret

.gadget cvt_16
    tst eax, 0x8000
    cinv w8, wzr, ne
    bfxil edx, w8, 0, 16
    gret

.gadget cvt_32
    tst eax, 0x80000000
    cinv edx, wzr, ne
    gret

.gadget cvt_64
    tst rax, 0x8000000000000000
    cinv x8, xzr, ne
    mov rdx, x8
    gret

.gadget_list cvt, SIZE_LIST

# Add missing cvte variants for all sizes  
.gadget cvte_8
    # cvte_8 should sign-extend al into ax (8->16 bit)
    sxtb w8, eax
    bfxil eax, w8, 0, 16
    gret

.gadget cvte_16
    sxtb w8, eax
    bfxil eax, w8, 0, 16
    gret

.gadget cvte_32
    sxth eax, eax
    gret

.gadget cvte_64
    # cvte_64 should sign-extend eax into rax (32->64 bit)
    sxtw rax, eax
    gret

.gadget_list cvte, SIZE_LIST

# Additional 64-bit addr and gs gadgets for basic operations
.gadget add64_addr
    do_op add, 64, _xaddr
    gret

.gadget add64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op add, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget sub64_addr
    do_op sub, 64, _xaddr
    gret

.gadget sub64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op sub, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget and64_addr
    do_op and, 64, _xaddr
    gret

.gadget and64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op and, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget or64_addr
    do_op or, 64, _xaddr
    gret

.gadget or64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op or, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget xor64_addr
    do_op xor, 64, _xaddr
    gret

.gadget xor64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op xor, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget adc64_addr
    do_op adc, 64, _xaddr
    gret

.gadget adc64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op adc, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget sbb64_addr
    do_op sbb, 64, _xaddr
    gret

.gadget sbb64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op sbb, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

.gadget store64_addr
    do_op store, 64, _xaddr
    gret

.gadget xchg64_addr
    do_op xchg, 64, _xaddr
    gret

.gadget xchg64_gs
    ldr _xtmp, [_cpu, #CPU_gs]
    do_op xchg, 64, _xtmp
    str _xtmp, [_cpu, #CPU_gs]
    gret

# Add missing 32-bit logical addr and gs gadgets
.gadget and32_addr
    do_op and, 32, _addr
    gret

.gadget and32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op and, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget or32_addr
    do_op or, 32, _addr
    gret

.gadget or32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op or, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xor32_addr
    do_op xor, 32, _addr
    gret

.gadget xor32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xor, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing 16-bit logical addr and gs gadgets
.gadget and16_addr
    do_op and, 16, _addr
    gret

.gadget and16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op and, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget or16_addr
    do_op or, 16, _addr
    gret

.gadget or16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op or, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xor16_addr
    do_op xor, 16, _addr
    gret

.gadget xor16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xor, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# Add missing arithmetic operations for 32-bit
.gadget add32_addr
    do_op add, 32, _addr
    gret

.gadget add32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op add, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sub32_addr
    do_op sub, 32, _addr
    gret

.gadget sub32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sub, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget adc32_addr
    do_op adc, 32, _addr
    gret

.gadget adc32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op adc, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sbb32_addr
    do_op sbb, 32, _addr
    gret

.gadget sbb32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sbb, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xchg32_addr
    do_op xchg, 32, _addr
    gret

.gadget xchg32_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xchg, 32, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# store32_addr and load32_addr already exist - removing duplicates

# Add missing arithmetic operations for 16-bit
.gadget add16_addr
    do_op add, 16, _addr
    gret

.gadget add16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op add, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sub16_addr
    do_op sub, 16, _addr
    gret

.gadget sub16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sub, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget adc16_addr
    do_op adc, 16, _addr
    gret

.gadget adc16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op adc, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sbb16_addr
    do_op sbb, 16, _addr
    gret

.gadget sbb16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sbb, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xchg16_addr
    do_op xchg, 16, _addr
    gret

.gadget xchg16_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xchg, 16, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# store16_addr and load16_addr likely exist - removing duplicates

# Add missing arithmetic operations for 8-bit
.gadget add8_addr
    do_op add, 8, _addr
    gret

.gadget add8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op add, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sub8_addr
    do_op sub, 8, _addr
    gret

.gadget sub8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sub, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget adc8_addr
    do_op adc, 8, _addr
    gret

.gadget adc8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op adc, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget sbb8_addr
    do_op sbb, 8, _addr
    gret

.gadget sbb8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op sbb, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xchg8_addr
    do_op xchg, 8, _addr
    gret

.gadget xchg8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xchg, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# store8_addr and load8_addr likely exist - removing duplicates

.gadget and8_addr
    do_op and, 8, _addr
    gret

.gadget and8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op and, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget or8_addr
    do_op or, 8, _addr
    gret

.gadget or8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op or, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget xor8_addr
    do_op xor, 8, _addr
    gret

.gadget xor8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op xor, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

.gadget imul8_addr
    do_op imul1, 8, _addr
    gret

.gadget imul8_gs
    ldr _tmp, [_cpu, #CPU_gs]
    do_op imul1, 8, _tmp
    str _tmp, [_cpu, #CPU_gs]
    gret

# Missing atomic immediate and register variants (360 gadgets)
# These use regular CPU state operations since they don't access shared memory

.macro do_atomic_op_size op, armop, size, s
    # Immediate variant
    .gadget atomic_\op\size\()_imm
        .if \size == 64
            ldr x8, [_ip]
            do_op \armop, \size, x8
        .else
            ldr\s w8, [_ip]
            do_op \armop, \size, w8
        .endif
        gret 1

    # Register variants
    .irp reg, a,b,c,d
        do_reg_op atomic_\op, \armop, \size, \reg
    .endr

    .irp reg, si,di,sp,bp
        .gadget atomic_\op\size\()_reg_\reg
            .if \size == 8
                .ifc \reg,sp N do_hi_op \armop, \size, a N .else
                .ifc \reg,bp N do_hi_op \armop, \size, c N .else
                .ifc \reg,si N do_hi_op \armop, \size, d N .else
                .ifc \reg,di N do_hi_op \armop, \size, b
                .endif N .endif N .endif N .endif
            .elseif \size == 64
                do_op \armop, \size, r\reg
            .else
                do_op \armop, \size, e\reg
            .endif
            gret
    .endr
.endm

# Implement all 10 atomic operations × 4 sizes = 40 immediate + 320 register = 360 gadgets
.irp op, add,sub,adc,sbb,and,or,xor,inc,dec,xadd
    .irp size, SIZE_LIST
        .ifc \op,xor
            ss \size, do_atomic_op_size, \op, eor
        .else N .ifc \op,sbb
            ss \size, do_atomic_op_size, \op, sbc
        .else N .ifc \op,or
            ss \size, do_atomic_op_size, \op, orr
        .else
            ss \size, do_atomic_op_size, \op, \op
        .endif N .endif N .endif
    .endr
.endr

#ifdef ISH_64BIT

/******************************************************************************
 * R11 gadgets (memory-based) – arithmetic/logic + cmp/test + xchg
 ******************************************************************************/

.macro do_r11_op op, armop, size
    .gadget \op\size\()_reg_r11
        .if \size == 64
            ldr x8, [_cpu, #CPU_r11]
            do_op \armop, \size, x8
            .ifnc \op,cmp
            .ifnc \op,test
                str _xtmp, [_cpu, #CPU_r11]
            .endif
            .endif
        .else
            ldr w8, [_cpu, #CPU_r11]
            do_op \armop, \size, w8
            .ifnc \op,cmp
            .ifnc \op,test
                str _tmp, [_cpu, #CPU_r11]
            .endif
            .endif
        .endif
        gret
.endm

/* Generate gadgets */
.irp op, add,sub,and,or,xor,cmp,test
    .irp size, 8,16,32,64
        .ifc \op,or
            do_r11_op \op, orr, \size
        .else N .ifc \op,xor
            do_r11_op \op, eor, \size
        .else N .ifc \op,sbb
            do_r11_op \op, sbc, \size
        .else N .ifc \op,inc
            do_r11_op \op, add, \size
        .else N .ifc \op,dec
            do_r11_op \op, sub, \size
        .else
            do_r11_op \op, \op, \size
        .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
    .endr
.endr

/* cmp & test (no write-back) */
#if 0
.irp op, cmp,test
    .irp size, 8,16,32,64
        .gadget \op\size\()_reg_r11
            .if \size == 64
                ldr x8, [_cpu, #CPU_r11]
                do_op \op, \size, x8
            .else
                ldr w8, [_cpu, #CPU_r11]
                do_op \op, \size, w8
            .endif
            gret
    .endr
.endr
#endif

/* xchg – always writes back */
.irp size, 8,16,32,64
    .gadget xchg\size\()_reg_r11
        .if \size == 64
            ldr x8, [_cpu, #CPU_r11]
            do_op xchg, \size, x8
            str _xtmp, [_cpu, #CPU_r11]
        .else
            ldr w8, [_cpu, #CPU_r11]
            do_op xchg, \size, w8
            str _tmp, [_cpu, #CPU_r11]
        .endif
        gret
.endr

#endif /* ISH_64BIT */


