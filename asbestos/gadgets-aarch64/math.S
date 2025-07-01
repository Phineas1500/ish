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
                uxtw x10, \arg
            .else
                uxt\s w10, \arg
            .endif
        .else
            mov w10, \arg
        .endif
        .ifc \op,bsf
            .if \size != 32
                orr w10, w10, 1<<\size
            .endif
            rbit w10, w10
            clz w10, w10
            cmp w10, \size
        .else
            clz w10, w10
            .if \size != 32
                sub w10, w10, 32-\size
            .endif
            cmp w10, \size
            mov w9, \size-1
            sub w10, w9, w10
        .endif
        .if \size == 64
            csel _xtmp, w10, _xtmp, ne
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
# imul now supports 64-bit with ARM64 fixes
.irp op, imul
    .irp size, 16,32,64
        ss \size, do_op_size, \op, \op
    .endr
    .gadget_array \op
.endr
# bsf,bsr still have ARM64 64-bit issues - keep at 16,32 for now
.irp op, bsf,bsr
    .irp size, 16,32
        ss \size, do_op_size, \op, \op
    .endr
    .gadget_array \op
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

.gadget cvt_16
    tst eax, 0x8000
    cinv w8, wzr, ne
    bfxil edx, w8, 0, 16
    gret
.gadget cvt_32
    tst eax, 0x80000000
    cinv edx, wzr, ne
    gret
.gadget_list cvt, SIZE_LIST

.gadget cvte_16
    sxtb w8, eax
    bfxil eax, w8, 0, 16
    gret
.gadget cvte_32
    sxth eax, eax
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
