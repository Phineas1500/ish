.macro do_add op, dst, src, s
    # setting flags: a horror story
    .ifb \s
        # for 32-bit operands, we can just do the operation and the chip
        # will set v and c right, which we copy
        \op\()s \dst, \dst, \src
        cset w10, vs
        strb w10, [_cpu, CPU_of]
        .ifin(\op, add,adc)
            cset w10, cs
        .endifin
        .ifin(\op, sub,sbc)
            cset w10, cc
        .endifin
        strb w10, [_cpu, CPU_cf]
    .else
        # for 16 or 8 bit operands...
        # first figure out unsigned overflow
        .ifc \s,x
            uxtw x10, \dst
        .else
            uxt\s w10, \dst
        .endif
        .ifin(\op, add,sub)
            .ifc \s,x
                uxtw x11, \src
                \op x10, x10, x11
            .else
                \op w10, w10, \src, uxt\s
            .endif
        .endifin
        .ifin(\op, adc,sbc)
            .ifc \s,x
                uxtw x9, \src
                \op x10, x10, x9
            .else
                uxt\s w9, \src
                \op w10, w10, w9
            .endif
        .endifin
        .ifc \s,b
            lsr w10, w10, 8
        .else N .ifc \s,x
            lsr x10, x10, 32
        .else
            lsr w10, w10, 16
        .endif N .endif
        .ifc \s,x
            # extract low 32 bits from x10
            mov w10, w10
        .endif
        strb w10, [_cpu, CPU_cf]
        # now signed overflow
        .ifc \s,x
            sxtw x10, \dst
        .else
            sxt\s w10, \dst
        .endif
        .ifin(\op, add,sub)
            .ifc \s,x
                sxtw x12, \src
                \op x11, x10, x12
            .else
                \op \dst, w10, \src, sxt\s
            .endif
        .endifin
        .ifin(\op, adc,sbc)
            # help me
            .ifc \s,x
                sxtw x9, \src
                \op x11, x10, x9
            .else
                sxt\s w9, \src
                \op \dst, w10, w9
            .endif
        .endifin
        .ifc \s,x
            # compare 64-bit result with sign-extended 32-bit version to detect overflow
            sxtw x13, w11
            cmp x11, x13
            # store low 32 bits back - handle specific known register cases
            .ifc \dst,_xtmp
                uxtw \dst, w11
            .else N .ifc \dst,x8
                uxtw \dst, w11
            .else N .ifc \dst,x9
                uxtw \dst, w11
            .else N .ifc \dst,x10
                uxtw \dst, w11
            .else N .ifc \dst,x11
                uxtw \dst, w11
            .else N .ifc \dst,x12
                uxtw \dst, w11
            .else
                mov \dst, w11
            .endif N .endif N .endif N .endif N .endif N .endif
        .else
            cmp \dst, \dst, sxt\s
        .endif
        cset w10, ne
        strb w10, [_cpu, CPU_of]
    .endif
.endm

# vim: ft=gas
