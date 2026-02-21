#include "emu/cpu.h"
#include "kernel/calls.h"
#include "kernel/task.h"
#include <stdio.h>
#include <string.h>

// Debug output guard: define DEBUG_64BIT_VERBOSE=1 to enable verbose debug
// output
#ifndef DEBUG_64BIT_VERBOSE
#define DEBUG_64BIT_VERBOSE 0
#endif

#if DEBUG_64BIT_VERBOSE
#define DEBUG_FPRINTF(...) fprintf(__VA_ARGS__)
#else
#define DEBUG_FPRINTF(...) ((void)0)
#endif
#define PRCTL_SET_KEEPCAPS_ 8
#define PRCTL_SET_NAME_ 15

int_t sys_prctl(dword_t option, uint_t arg2, uint_t UNUSED(arg3),
                uint_t UNUSED(arg4), uint_t UNUSED(arg5)) {
  switch (option) {
  case PRCTL_SET_KEEPCAPS_:
    // stub
    return 0;
  case PRCTL_SET_NAME_: {
    char name[16];
    if (user_read_string(arg2, name, sizeof(name) - 1))
      return _EFAULT;
    name[sizeof(name) - 1] = '\0';
    STRACE("prctl(PRCTL_SET_NAME, \"%s\")", name);
    strcpy(current->comm, name);
    return 0;
  }
  default:
    STRACE("prctl(%#x)", option);
    return _EINVAL;
  }
}

#ifdef ISH_GUEST_64BIT
// 64-bit prctl: arg2 can be a pointer (e.g., PR_SET_NAME) which needs full 64-bit width
int_t sys_prctl64(dword_t option, addr_t arg2, addr_t UNUSED(arg3),
                  addr_t UNUSED(arg4), addr_t UNUSED(arg5)) {
  switch (option) {
  case PRCTL_SET_KEEPCAPS_:
    return 0;
  case PRCTL_SET_NAME_: {
    char name[16];
    if (user_read_string(arg2, name, sizeof(name) - 1))
      return _EFAULT;
    name[sizeof(name) - 1] = '\0';
    STRACE("prctl(PRCTL_SET_NAME, \"%s\")", name);
    strcpy(current->comm, name);
    return 0;
  }
  default:
    STRACE("prctl(%#x)", option);
    return _EINVAL;
  }
}
#endif

// arch_prctl codes
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

int_t sys_arch_prctl(int_t code, addr_t addr) {
#ifdef ISH_GUEST_64BIT
  struct cpu_state *cpu = &current->cpu;
  switch (code) {
  case ARCH_SET_FS:
    STRACE("arch_prctl(ARCH_SET_FS, " ADDR_FMT ")", addr);
    DEBUG_FPRINTF(
        stderr,
        "ARCH_SET_FS: addr=0x%llx fs_base offset=%lu sizeof(fs_base)=%lu\n",
        (unsigned long long)addr,
        (unsigned long)offsetof(struct cpu_state, fs_base),
        (unsigned long)sizeof(cpu->fs_base));
    cpu->fs_base = addr;
    DEBUG_FPRINTF(stderr, "ARCH_SET_FS: after store, fs_base=0x%llx\n",
                  (unsigned long long)cpu->fs_base);
    return 0;
  case ARCH_GET_FS:
    STRACE("arch_prctl(ARCH_GET_FS, " ADDR_FMT ")", addr);
    if (user_put(addr, cpu->fs_base))
      return _EFAULT;
    return 0;
  case ARCH_SET_GS:
    STRACE("arch_prctl(ARCH_SET_GS, " ADDR_FMT ")", addr);
    cpu->gs_base = addr;
    return 0;
  case ARCH_GET_GS:
    STRACE("arch_prctl(ARCH_GET_GS, " ADDR_FMT ")", addr);
    if (user_put(addr, cpu->gs_base))
      return _EFAULT;
    return 0;
  default:
    STRACE("arch_prctl(%#x, " ADDR_FMT ")", code, addr);
    return _EINVAL;
  }
#else
  // 32-bit x86 doesn't use arch_prctl for TLS (uses set_thread_area instead)
  STRACE("arch_prctl(%#x, %#x)", code, addr);
  return _EINVAL;
#endif
}

#define REBOOT_MAGIC1 0xfee1dead
#define REBOOT_MAGIC2 672274793
#define REBOOT_MAGIC2A 85072278
#define REBOOT_MAGIC2B 369367448
#define REBOOT_MAGIC2C 537993216

#define REBOOT_CMD_CAD_OFF 0
#define REBOOT_CMD_CAD_ON 0x89abcdef

int_t sys_reboot(int_t magic, int_t magic2, int_t cmd) {
  STRACE("reboot(%#x, %d, %d)", magic, magic2, cmd);
  if (!superuser())
    return _EPERM;
  if (magic != (int)REBOOT_MAGIC1 ||
      (magic2 != REBOOT_MAGIC2 && magic2 != REBOOT_MAGIC2A &&
       magic2 != REBOOT_MAGIC2B && magic2 != REBOOT_MAGIC2C))
    return _EINVAL;

  switch (cmd) {
  case REBOOT_CMD_CAD_ON:
  case REBOOT_CMD_CAD_OFF:
    return 0;
  default:
    return _EPERM;
  }
}
