#include "gadgets.h"
#include "math.h"

.gadget cpuid
    # regrettable
    save_c
    sub sp, sp, 0x10
    str eax, [sp, 0xc]
    str ebx, [sp, 0x8]
    str ecx, [sp, 0x4]
    str edx, [sp, 0x0]
    add x0, sp, 0xc
    add x1, sp, 0x8
    add x2, sp, 0x4
    mov x3, sp
    bl NAME(helper_cpuid)
    ldr eax, [sp, 0xc]
    ldr ebx, [sp, 0x8]
    ldr ecx, [sp, 0x4]
    ldr edx, [sp, 0x0]
    add sp, sp, 0x10
    restore_c
    gret

.macro do_cmpxchg size, s
    .gadget cmpxchg\size\()_mem
        write_prep \size, cmpxchg\size\()_mem
        .if \size == 64
            ldr x8, [_xaddr]
        .else
            ldr\s w8, [_xaddr]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        cset w9, eq
        .if \size == 64
            str x8, [_xaddr]
        .else
            str\s w8, [_xaddr]
        .endif
        write_done \size, cmpxchg\size\()_mem
        gret 1
        write_bullshit \size, cmpxchg\size\()_mem

    .gadget atomic_cmpxchg\size\()_mem
        write_prep \size, atomic_cmpxchg\size\()_mem
        mov w12, eax
        ldr w11, [_xaddr]
    1:
        mov w8, w11
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        cset w9, eq

        # all that setf stuff writes to memory which means instead of just using
        # ldaxr and stlxr we now have to do *another* compare-and-exchange
    2:
        .if \size == 64
            ldaxr x10, [_xaddr]
        .else
            ldaxr\s w10, [_xaddr]
        .endif
        cmp w10, w11
        b.ne 3f
        .if \size == 64
            stlxr w10, x8, [_xaddr]
        .else
            stlxr\s w10, w8, [_xaddr]
        .endif
        cbnz w10, 2b

        write_done \size, atomic_cmpxchg\size\()_mem
        gret 1
        write_bullshit \size, atomic_cmpxchg\size\()_mem
    3:
        dmb ish
        mov w11, w10
        mov eax, w12
        b 1b

    # Add missing addr variant - fall back to non-atomic for atomic version
    .gadget cmpxchg\size\()_addr
        .if \size == 64
            ldr x8, [_xaddr]
        .else
            ldr\s w8, [_xaddr]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        .if \size == 64
            str x8, [_xaddr]
        .else
            str\s w8, [_xaddr]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_addr
        # Fall back to non-atomic for simplicity
        .if \size == 64
            ldr x8, [_xaddr]
        .else
            ldr\s w8, [_xaddr]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        .if \size == 64
            str x8, [_xaddr]
        .else
            str\s w8, [_xaddr]
        .endif
        gret

    # Add missing gs variant
    .gadget cmpxchg\size\()_gs
        .if \size == 64
            ldr x10, [_cpu, #CPU_gs]
            ldr x8, [x10]
            str x8, [_cpu, #CPU_gs]
        .else
            ldr w10, [_cpu, #CPU_gs]
            ldr\s w8, [x10]
            str w8, [_cpu, #CPU_gs]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        gret

    .gadget atomic_cmpxchg\size\()_gs
        # Fall back to non-atomic gs variant
        .if \size == 64
            ldr x10, [_cpu, #CPU_gs]
            ldr x8, [x10]
            str x8, [_cpu, #CPU_gs]
        .else
            ldr w10, [_cpu, #CPU_gs]
            ldr\s w8, [x10]
            str w8, [_cpu, #CPU_gs]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        gret

    # Add missing imm variant
    .gadget cmpxchg\size\()_imm
        .if \size == 64
            ldr x8, [_ip]
        .else
            ldr\s w8, [_ip]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        gret 1

    .gadget atomic_cmpxchg\size\()_imm
        # Fall back to non-atomic imm variant
        .if \size == 64
            ldr x8, [_ip]
        .else
            ldr\s w8, [_ip]
        .endif
        setf_a eax, w8
        mov w9, eax
        do_add sub, w9, w8, \s
        setf_zsp \s, val=w9
        .ifnb \s
            cmp w9, 0
            .if \size != 64
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
        .endif
        csel eax, w8, eax, ne
        csel w8, _tmp, w8, eq
        gret 1

    # Add missing register variants
    .macro x name, reg
        .gadget cmpxchg\size\()_\name
            .if \size == 64
                setf_a eax, \reg
                mov w9, eax
                do_add sub, w9, \reg, \s
                setf_zsp \s, val=w9
                csel eax, \reg, eax, ne
                csel \reg, _tmp, \reg, eq
            .else
                setf_a eax, \reg
                mov w9, eax
                do_add sub, w9, \reg, \s
                setf_zsp \s, val=w9
                .ifnb \s
                    cmp w9, 0
                    .if \size != 64
                        and w9, eax, (-1 << \size)
                        orr \reg, \reg, w9
                    .endif
                .endif
                csel eax, \reg, eax, ne
                csel \reg, _tmp, \reg, eq
            .endif
            gret

        .gadget atomic_cmpxchg\size\()_\name
            # Fall back to non-atomic register variant
            .if \size == 64
                setf_a eax, \reg
                mov w9, eax
                do_add sub, w9, \reg, \s
                setf_zsp \s, val=w9
                csel eax, \reg, eax, ne
                csel \reg, _tmp, \reg, eq
            .else
                setf_a eax, \reg
                mov w9, eax
                do_add sub, w9, \reg, \s
                setf_zsp \s, val=w9
                .ifnb \s
                    cmp w9, 0
                    .if \size != 64
                        and w9, eax, (-1 << \size)
                        orr \reg, \reg, w9
                    .endif
                .endif
                csel eax, \reg, eax, ne
                csel \reg, _tmp, \reg, eq
            .endif
            gret
    .endm
    .each_reg x
    .purgem x
.endm

.irp size, SIZE_LIST
    ss \size, do_cmpxchg
.endr
.gadget_array cmpxchg

.extern segfault_write

.gadget atomic_cmpxchg8b
    # Test for alignment.
    tst _addr, 0x7
    b.ne 3f

    # cmpxchg8b via aligned exclusive 8b load
    write_prep 64, atomic_cmpxchg8b

    # load parameters: x10 = edx:eax (old value), x11 = ecx:ebx (new value)
    mov w10, eax
    bfi x10, xdx, 32, 32
    mov w11, ebx
    bfi x11, xcx, 32, 32

    # run operation: load to x9, compare with x10, store x11. short circuit if comparison fails.
1:
    ldaxr x9, [_xaddr]
    cmp x10, x9
    b.ne 1f
    stlxr w12, x11, [_xaddr]
    cbnz w12, 1b
1:
    cset w12, eq

    # edx:eax should always get set to the value last seen in memory (x9)
    write_done 64, atomic_cmpxchg8b
    ubfx xax, x9, 0, 32
    ubfx xdx, x9, 32, 32

    # set flags (but only zf)
    ldr w8, [_cpu, CPU_flags_res]
    ldr w9, [_cpu, CPU_eflags]
    and w8, w8, ~ZF_RES
    bfi w9, w12, 6, 1
    str w8, [_cpu, CPU_flags_res]
    str w9, [_cpu, CPU_eflags]
    gret 1
    write_bullshit 64, atomic_cmpxchg8b

3:  # All unaligned paths
    b segfault_write


.gadget cmpxchg8b
    write_prep 64, cmpxchg8b
    mov w9, eax
    bfi x9, xdx, 32, 32
    mov w10, ebx
    bfi x10, xcx, 32, 32

    ldr x8, [_xaddr]
    cmp x9, x8
    csel x9, x8, x9, ne
    csel x8, x10, x8, eq
    cset w11, eq
    str x8, [_xaddr]
    write_done 64, cmpxchg8b
    ubfx xax, x9, 0, 32
    ubfx xdx, x9, 32, 32

    ldr w8, [_cpu, CPU_flags_res]
    ldr w9, [_cpu, CPU_eflags]
    and w8, w8, ~ZF_RES
    bfi w9, w11, 6, 1
    str w8, [_cpu, CPU_flags_res]
    str w9, [_cpu, CPU_eflags]
    gret 1
    write_bullshit 64, cmpxchg8b

.macro do_helper type, size=
    .gadget helper_\type\size
        .ifin(\type, read,write)
            \type\()_prep (\size), helper_\type\size
        .endifin
        save_regs
        save_c
        mov x0, _cpu
        .ifc \type,1
            ldr x1, [_ip, 8]
        .endif
        .ifc \type,2
            ldr x1, [_ip, 8]
            ldr x2, [_ip, 16]
        .endif
        .ifin(\type, read,write)
            mov x1, _xaddr
            ldr x8, [_ip, 8]
        .endifin
        .ifin(\type, 0,1,2)
            ldr x8, [_ip]
        .endifin
        blr x8
        restore_c
        load_regs
        .ifc \type,write
            write_done (\size), helper_\type\size
        .endif
        .ifc \type,0
            gret 1
        .else N .ifc \type,2
            gret 3
        .else
            gret 2
        .endif N .endif
        .ifc \type,read
            read_bullshit (\size), helper_\type\size
        .else N .ifc \type,write
            write_bullshit (\size), helper_\type\size
        .endif N .endif
.endm
do_helper 0
do_helper 1
do_helper 2
.irp size, SIZE_LIST,80
    do_helper read, \size
    do_helper write, \size
.endr

.macro do_vec_helper rm, _imm, size=
    .gadget vec_helper_\rm\size\_imm
        .ifin(\rm, read,write)
            \rm\()_prep (\size), vec_helper_\rm\size\_imm
        .endifin
        save_regs
        save_c
        mov x0, _cpu

        # the argument order should be a consistent src, dst
        .ifc \rm,reg
            # src
            ldrh w1, [_ip, 8]
            add x1, x0, x1
            # dst
            ldrh w2, [_ip, 10]
            add x2, x0, x2
        .endif
        .ifc \rm,read
            # src
            mov x1, _xaddr
            # dst
            ldrh w2, [_ip, 16]
            add x2, x0, x2
        .endif
        .ifc \rm,write
            # src
            ldrh w1, [_ip, 16]
            add x1, x0, x1
            # dst
            mov x2, _xaddr
        .endif
        .ifc \rm,imm
            # src
            ldrh w1, [_ip, 8]
            # dst
            ldrh w2, [_ip, 10]
            add x2, x0, x2
        .endif

        .ifc _imm,_imm
            # imm for third argument
            .ifin(\rm, reg)
                ldr w3, [_ip, 12]
            .endifin
            .ifin(\rm, read,write)
                ldr w3, [_ip, 20]
            .endifin
        .endif

        .ifin(\rm, read,write)
            ldr x8, [_ip, 8]
        .endifin
        .ifin(\rm, reg,imm)
            ldr x8, [_ip]
        .endifin
        blr x8

        restore_c
        load_regs
        .ifc \rm,write
            write_done (\size), vec_helper_\rm\size\_imm
        .endif
        .ifin(\rm, reg,imm)
            gret 2
        .endifin
        .ifin(\rm, read,write)
            gret 3
        .endifin
        .ifc \rm,read
            read_bullshit (\size), vec_helper_\rm\size\_imm
        .else N .ifc \rm,write
            write_bullshit (\size), vec_helper_\rm\size\_imm
        .endif N .endif
.endm

.irp _imm, ,_imm
    .irp rm, reg,imm
        do_vec_helper \rm, \_imm
    .endr
    .irp size, SIZE_LIST,128
        do_vec_helper read, \_imm, \size
        do_vec_helper write, \_imm, \size
    .endr
.endr

.gadget fstsw_ax
    ldrh w10, [_cpu, CPU_fsw]
    mov eax, w10
    gret

.gadget_array atomic_cmpxchg

#ifdef ISH_64BIT
/* R11 cmpxchg operations */
.irp size, 8,16,32,64
    .gadget cmpxchg\size\()_reg_r11
        .if \size == 64
            ldr x8, [_cpu, #CPU_r11]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r11]
        .else
            ldr w8, [_cpu, #CPU_r11]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r11]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_reg_r11
        # Fall back to non-atomic register variant
        .if \size == 64
            ldr x8, [_cpu, #CPU_r11]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r11]
        .else
            ldr w8, [_cpu, #CPU_r11]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r11]
        .endif
        gret
.endr

.irp size, 8,16,32,64
    .gadget cmpxchg\size\()_reg_r12
        .if \size == 64
            ldr x8, [_cpu, #CPU_r12]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r12]
        .else
            ldr w8, [_cpu, #CPU_r12]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r12]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_reg_r12
        # Fall back to non-atomic register variant
        .if \size == 64
            ldr x8, [_cpu, #CPU_r12]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r12]
        .else
            ldr w8, [_cpu, #CPU_r12]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r12]
        .endif
        gret
.endr

.irp size, 8,16,32,64
    .gadget cmpxchg\size\()_reg_r13
        .if \size == 64
            ldr x8, [_cpu, #CPU_r13]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r13]
        .else
            ldr w8, [_cpu, #CPU_r13]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r13]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_reg_r13
        # Fall back to non-atomic register variant
        .if \size == 64
            ldr x8, [_cpu, #CPU_r13]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r13]
        .else
            ldr w8, [_cpu, #CPU_r13]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r13]
        .endif
        gret
.endr

.irp size, 8,16,32,64
    .gadget cmpxchg\size\()_reg_r14
        .if \size == 64
            ldr x8, [_cpu, #CPU_r14]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r14]
        .else
            ldr w8, [_cpu, #CPU_r14]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r14]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_reg_r14
        # Fall back to non-atomic register variant
        .if \size == 64
            ldr x8, [_cpu, #CPU_r14]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r14]
        .else
            ldr w8, [_cpu, #CPU_r14]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r14]
        .endif
        gret
.endr

.irp size, 8,16,32,64
    .gadget cmpxchg\size\()_reg_r15
        .if \size == 64
            ldr x8, [_cpu, #CPU_r15]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r15]
        .else
            ldr w8, [_cpu, #CPU_r15]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r15]
        .endif
        gret

    .gadget atomic_cmpxchg\size\()_reg_r15
        # Fall back to non-atomic register variant
        .if \size == 64
            ldr x8, [_cpu, #CPU_r15]
            setf_a eax, w8
            mov w9, eax
            do_add sub, w9, w8, x
            setf_zsp x, val=w9
            csel eax, w8, eax, ne
            csel x8, _xtmp, x8, eq
            str x8, [_cpu, #CPU_r15]
        .else
            ldr w8, [_cpu, #CPU_r15]
            setf_a eax, w8
            mov w9, eax
            .if \size == 8
                do_add sub, w9, w8, b
                setf_zsp b, val=w9
            .elseif \size == 16
                do_add sub, w9, w8, h
                setf_zsp h, val=w9
            .else
                do_add sub, w9, w8,
                setf_zsp "", val=w9
            .endif
            .if \size != 32
                cmp w9, 0
                and w9, eax, (-1 << \size)
                orr w8, w8, w9
            .endif
            csel eax, w8, eax, ne
            csel w8, _tmp, w8, eq
            str w8, [_cpu, #CPU_r15]
        .endif
        gret
.endr
#endif /* ISH_64BIT */