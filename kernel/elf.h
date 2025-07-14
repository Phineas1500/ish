#ifndef ELF_H
#define ELF_H

#include "misc.h"

#define ELF_MAGIC "\177ELF"
#define ELF_32BIT 1
#define ELF_64BIT 2
#define ELF_LITTLEENDIAN 1
#define ELF_BIGENDIAN 2
#define ELF_LINUX_ABI 3
#define ELF_EXECUTABLE 2
#define ELF_DYNAMIC 3
#define ELF_X86 3
#define ELF_X86_64 62

// Relocation types for x86_64
#define R_X86_64_NONE     0
#define R_X86_64_64       1
#define R_X86_64_PC32     2
#define R_X86_64_GOT32    3
#define R_X86_64_PLT32    4
#define R_X86_64_COPY     5
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE 8

// Dynamic section tags
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_JMPREL   17

struct elf_header {
    uint32_t magic;
    byte_t bitness;
    byte_t endian;
    byte_t elfversion1;
    byte_t abi;
    byte_t abi_version;
    byte_t padding[7];
    uint16_t type; // library or executable or what
    uint16_t machine;
    uint32_t elfversion2;
    dword_t entry_point;
    dword_t prghead_off;
    dword_t secthead_off;
    uint32_t flags;
    uint16_t header_size;
    uint16_t phent_size;
    uint16_t phent_count;
    uint16_t shent_size;
    uint16_t shent_count;
    uint16_t sectname_index;
};

// 64-bit ELF header structure
struct elf_header_64 {
    uint32_t magic;
    byte_t bitness;
    byte_t endian;
    byte_t elfversion1;
    byte_t abi;
    byte_t abi_version;
    byte_t padding[7];
    uint16_t type;
    uint16_t machine;
    uint32_t elfversion2;
    uint64_t entry_point;
    uint64_t prghead_off;
    uint64_t secthead_off;
    uint32_t flags;
    uint16_t header_size;
    uint16_t phent_size;
    uint16_t phent_count;
    uint16_t shent_size;
    uint16_t shent_count;
    uint16_t sectname_index;
};

// Union to handle both 32-bit and 64-bit headers
union elf_header_any {
    struct elf_header h32;
    struct elf_header_64 h64;
};

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7
#define PT_NUM 8

struct prg_header {
    uint32_t type;
    dword_t offset;
    dword_t vaddr;
    dword_t paddr;
    dword_t filesize;
    dword_t memsize;
    uint32_t flags;
    dword_t alignment; // must be power of 2
};

// 64-bit program header structure
struct prg_header_64 {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesize;
    uint64_t memsize;
    uint64_t alignment;
};

// Union to handle both 32-bit and 64-bit program headers
union prg_header_any {
    struct prg_header h32;
    struct prg_header_64 h64;
};

// Unified ELF header structure - holds common fields as 64-bit for compatibility
struct elf_header_unified {
    uint32_t magic;
    byte_t bitness;
    byte_t endian;
    byte_t elfversion1;
    byte_t abi;
    byte_t abi_version;
    byte_t padding[7];
    uint16_t type;
    uint16_t machine;
    uint32_t elfversion2;
    uint64_t entry_point;    // 64-bit to accommodate both formats
    uint64_t prghead_off;    // 64-bit to accommodate both formats
    uint64_t secthead_off;   // 64-bit to accommodate both formats
    uint32_t flags;
    uint16_t header_size;
    uint16_t phent_size;
    uint16_t phent_count;
    uint16_t shent_size;
    uint16_t shent_count;
    uint16_t sectname_index;
};

// Unified program header structure - holds common fields as 64-bit for compatibility
struct prg_header_unified {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;     // 64-bit to accommodate both formats
    uint64_t vaddr;      // 64-bit to accommodate both formats
    uint64_t paddr;      // 64-bit to accommodate both formats
    uint64_t filesize;   // 64-bit to accommodate both formats
    uint64_t memsize;    // 64-bit to accommodate both formats
    uint64_t alignment;  // 64-bit to accommodate both formats
};

#define PH_R (1 << 2)
#define PH_W (1 << 1)
#define PH_X (1 << 0)

struct aux_ent {
    uint32_t type;
    uint32_t value;
};

// 64-bit auxiliary vector entry structure
struct aux_ent_64 {
    uint64_t type;
    uint64_t value;
};

#define AX_PHDR 3
#define AX_PHENT 4
#define AX_PHNUM 5
#define AX_PAGESZ 6
#define AX_BASE 7
#define AX_FLAGS 8
#define AX_ENTRY 9
#define AX_UID 11
#define AX_EUID 12
#define AX_GID 13
#define AX_EGID 14
#define AX_PLATFORM 15
#define AX_HWCAP 16
#define AX_CLKTCK 17
#define AX_SECURE 23
#define AX_RANDOM 25
#define AX_HWCAP2 26
#define AX_EXECFN 31
#define AX_SYSINFO 32
#define AX_SYSINFO_EHDR 33

struct dyn_ent {
    dword_t tag;
    dword_t val;
};

#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6

struct elf_sym {
    uint32_t name;
    addr_t value;
    dword_t size;
    byte_t info;
    byte_t other;
    uint16_t shndx;
};

// 64-bit relocation structures for dynamic linking
struct elf_rela_64 {
    uint64_t offset;
    uint64_t info;
    int64_t addend;
};

struct elf_rel_64 {
    uint64_t offset;
    uint64_t info;
};

struct elf_sym_64 {
    uint32_t name;
    uint8_t info;
    uint8_t other;
    uint16_t shndx;
    uint64_t value;
    uint64_t size;
};

struct elf_dyn_64 {
    int64_t tag;
    union {
        uint64_t val;
        uint64_t ptr;
    } un;
};

// Macros for relocation info
#define ELF_R_SYM(info) ((info) >> 32)
#define ELF_R_TYPE(info) ((info) & 0xffffffff)

#endif
