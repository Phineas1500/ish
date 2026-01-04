#include "gadgets.h"

// Bitwise operations for 64-bit
// Phase 7a stub - will be expanded in Phase 7c

// Placeholder gadget arrays to satisfy linker
.pushsection_rodata
.global.name shl_gadgets
    .fill 60, 8, 0
.global.name shr_gadgets
    .fill 60, 8, 0
.global.name sar_gadgets
    .fill 60, 8, 0
.global.name rol_gadgets
    .fill 60, 8, 0
.global.name ror_gadgets
    .fill 60, 8, 0
.global.name rcl_gadgets
    .fill 60, 8, 0
.global.name rcr_gadgets
    .fill 60, 8, 0
.global.name and_gadgets
    .fill 60, 8, 0
.global.name or_gadgets
    .fill 60, 8, 0
.global.name xor_gadgets
    .fill 60, 8, 0
.global.name bt_gadgets
    .fill 60, 8, 0
.global.name bts_gadgets
    .fill 60, 8, 0
.global.name btr_gadgets
    .fill 60, 8, 0
.global.name btc_gadgets
    .fill 60, 8, 0
.global.name not_gadgets
    .fill 15, 8, 0
.global.name bswap_gadgets
    .fill 8, 8, 0
.popsection
