#include <string.h>
#include "debug.h"
#include "kernel/calls.h"
#include "emu/interrupt.h"
#include "kernel/memory.h"
#include "kernel/signal.h"
#include "kernel/task.h"

dword_t syscall_stub(void) {
    return _ENOSYS;
}
// While identical, this version of the stub doesn't log below. Use this for
// syscalls that are optional (i.e. fallback on something else) but called
// frequently.
dword_t syscall_silent_stub(void) {
    return _ENOSYS;
}
dword_t syscall_success_stub(void) {
    return 0;
}

#if is_gcc(8)
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
syscall_t syscall_table[] = {
    [1]   = (syscall_t) sys_exit,
    [2]   = (syscall_t) sys_fork,
    [3]   = (syscall_t) sys_read,
    [4]   = (syscall_t) sys_write,
    [5]   = (syscall_t) sys_open,
    [6]   = (syscall_t) sys_close,
    [7]   = (syscall_t) sys_waitpid,
    [9]   = (syscall_t) sys_link,
    [10]  = (syscall_t) sys_unlink,
    [11]  = (syscall_t) sys_execve,
    [12]  = (syscall_t) sys_chdir,
    [13]  = (syscall_t) sys_time,
    [14]  = (syscall_t) sys_mknod,
    [15]  = (syscall_t) sys_chmod,
    [19]  = (syscall_t) sys_lseek,
    [20]  = (syscall_t) sys_getpid,
    [21]  = (syscall_t) sys_mount,
    [23]  = (syscall_t) sys_setuid,
    [24]  = (syscall_t) sys_getuid,
    [25]  = (syscall_t) sys_stime,
    [26]  = (syscall_t) sys_ptrace,
    [27]  = (syscall_t) sys_alarm,
    [29]  = (syscall_t) sys_pause,
    [30]  = (syscall_t) sys_utime,
    [33]  = (syscall_t) sys_access,
    [36]  = (syscall_t) syscall_success_stub, // sync
    [37]  = (syscall_t) sys_kill,
    [38]  = (syscall_t) sys_rename,
    [39]  = (syscall_t) sys_mkdir,
    [40]  = (syscall_t) sys_rmdir,
    [41]  = (syscall_t) sys_dup,
    [42]  = (syscall_t) sys_pipe,
    [43]  = (syscall_t) sys_times,
    [45]  = (syscall_t) sys_brk,
    [46]  = (syscall_t) sys_setgid,
    [47]  = (syscall_t) sys_getgid,
    [49]  = (syscall_t) sys_geteuid,
    [50]  = (syscall_t) sys_getegid,
    [52]  = (syscall_t) sys_umount2,
    [54]  = (syscall_t) sys_ioctl,
    [55]  = (syscall_t) sys_fcntl32,
    [57]  = (syscall_t) sys_setpgid,
    [60]  = (syscall_t) sys_umask,
    [61]  = (syscall_t) sys_chroot,
    [63]  = (syscall_t) sys_dup2,
    [64]  = (syscall_t) sys_getppid,
    [65]  = (syscall_t) sys_getpgrp,
    [66]  = (syscall_t) sys_setsid,
    [74]  = (syscall_t) sys_sethostname,
    [75]  = (syscall_t) sys_setrlimit32,
    [76]  = (syscall_t) sys_old_getrlimit32,
    [77]  = (syscall_t) sys_getrusage,
    [78]  = (syscall_t) sys_gettimeofday,
    [79]  = (syscall_t) sys_settimeofday,
    [80]  = (syscall_t) sys_getgroups,
    [81]  = (syscall_t) sys_setgroups,
    [83]  = (syscall_t) sys_symlink,
    [85]  = (syscall_t) sys_readlink,
    [88]  = (syscall_t) sys_reboot,
    [90]  = (syscall_t) sys_mmap,
    [91]  = (syscall_t) sys_munmap,
    [94]  = (syscall_t) sys_fchmod,
    [96]  = (syscall_t) sys_getpriority,
    [97]  = (syscall_t) sys_setpriority,
    [99]  = (syscall_t) sys_statfs,
    [100] = (syscall_t) sys_fstatfs,
    [102] = (syscall_t) sys_socketcall,
    [103] = (syscall_t) sys_syslog,
    [104] = (syscall_t) sys_setitimer,
    [114] = (syscall_t) sys_wait4,
    [116] = (syscall_t) sys_sysinfo,
    [117] = (syscall_t) sys_ipc,
    [118] = (syscall_t) sys_fsync,
    [119] = (syscall_t) sys_sigreturn,
    [120] = (syscall_t) sys_clone,
    [122] = (syscall_t) sys_uname,
    [125] = (syscall_t) sys_mprotect,
    [132] = (syscall_t) sys_getpgid,
    [133] = (syscall_t) sys_fchdir,
    [136] = (syscall_t) sys_personality,
    [140] = (syscall_t) sys__llseek,
    [141] = (syscall_t) sys_getdents,
    [142] = (syscall_t) sys_select,
    [143] = (syscall_t) sys_flock,
    [144] = (syscall_t) sys_msync,
    [145] = (syscall_t) sys_readv,
    [146] = (syscall_t) sys_writev,
    [147] = (syscall_t) sys_getsid,
    [148] = (syscall_t) sys_fsync, // fdatasync
    [150] = (syscall_t) sys_mlock,
    [155] = (syscall_t) sys_sched_getparam,
    [156] = (syscall_t) sys_sched_setscheduler,
    [157] = (syscall_t) sys_sched_getscheduler,
    [158] = (syscall_t) sys_sched_yield,
    [159] = (syscall_t) sys_sched_get_priority_max,
    [162] = (syscall_t) sys_nanosleep,
    [163] = (syscall_t) sys_mremap,
    [168] = (syscall_t) sys_poll,
    [172] = (syscall_t) sys_prctl,
    [173] = (syscall_t) sys_rt_sigreturn,
    [174] = (syscall_t) sys_rt_sigaction,
    [175] = (syscall_t) sys_rt_sigprocmask,
    [176] = (syscall_t) sys_rt_sigpending,
    [177] = (syscall_t) sys_rt_sigtimedwait,
    [179] = (syscall_t) sys_rt_sigsuspend,
    [180] = (syscall_t) sys_pread,
    [181] = (syscall_t) sys_pwrite,
    [183] = (syscall_t) sys_getcwd,
    [184] = (syscall_t) sys_capget,
    [185] = (syscall_t) sys_capset,
    [186] = (syscall_t) sys_sigaltstack,
    [187] = (syscall_t) sys_sendfile,
    [190] = (syscall_t) sys_vfork,
    [191] = (syscall_t) sys_getrlimit32,
    [192] = (syscall_t) sys_mmap2,
    [193] = (syscall_t) sys_truncate64,
    [194] = (syscall_t) sys_ftruncate64,
    [195] = (syscall_t) sys_stat64,
    [196] = (syscall_t) sys_lstat64,
    [197] = (syscall_t) sys_fstat64,
    [198] = (syscall_t) sys_lchown,
    [199] = (syscall_t) sys_getuid32,
    [200] = (syscall_t) sys_getgid32,
    [201] = (syscall_t) sys_geteuid32,
    [202] = (syscall_t) sys_getegid32,
    [203] = (syscall_t) sys_setreuid,
    [204] = (syscall_t) sys_setregid,
    [205] = (syscall_t) sys_getgroups,
    [206] = (syscall_t) sys_setgroups,
    [207] = (syscall_t) sys_fchown32,
    [208] = (syscall_t) sys_setresuid,
    [209] = (syscall_t) sys_getresuid,
    [210] = (syscall_t) sys_setresgid,
    [211] = (syscall_t) sys_getresgid,
    [212] = (syscall_t) sys_chown32,
    [213] = (syscall_t) sys_setuid,
    [214] = (syscall_t) sys_setgid,
    [215] = (syscall_t) syscall_stub, // setfsuid
    [216] = (syscall_t) syscall_stub, // setfsgid
    [219] = (syscall_t) sys_madvise,
    [220] = (syscall_t) sys_getdents64,
    [221] = (syscall_t) sys_fcntl,
    [224] = (syscall_t) sys_gettid,
    [225] = (syscall_t) syscall_success_stub, // readahead
    [226 ... 237] = (syscall_t) sys_xattr_stub,
    [238] = (syscall_t) sys_tkill,
    [239] = (syscall_t) sys_sendfile64,
    [240] = (syscall_t) sys_futex,
    [241] = (syscall_t) sys_sched_setaffinity,
    [242] = (syscall_t) sys_sched_getaffinity,
    [243] = (syscall_t) sys_set_thread_area,
    [245] = (syscall_t) syscall_stub, // io_setup
    [252] = (syscall_t) sys_exit_group,
    [254] = (syscall_t) sys_epoll_create0,
    [255] = (syscall_t) sys_epoll_ctl,
    [256] = (syscall_t) sys_epoll_wait,
    [258] = (syscall_t) sys_set_tid_address,
    [259] = (syscall_t) sys_timer_create,
    [260] = (syscall_t) sys_timer_settime,
    [263] = (syscall_t) sys_timer_delete,
    [264] = (syscall_t) sys_clock_settime,
    [265] = (syscall_t) sys_clock_gettime,
    [266] = (syscall_t) sys_clock_getres,
    [268] = (syscall_t) sys_statfs64,
    [269] = (syscall_t) sys_fstatfs64,
    [270] = (syscall_t) sys_tgkill,
    [271] = (syscall_t) sys_utimes,
    [272] = (syscall_t) syscall_success_stub,
    [274] = (syscall_t) sys_mbind,
    [284] = (syscall_t) sys_waitid,
    [289] = (syscall_t) sys_ioprio_set,
    [290] = (syscall_t) sys_ioprio_get,
    [291] = (syscall_t) syscall_stub, // inotify_init
    [295] = (syscall_t) sys_openat,
    [296] = (syscall_t) sys_mkdirat,
    [297] = (syscall_t) sys_mknodat,
    [298] = (syscall_t) sys_fchownat,
    [300] = (syscall_t) sys_fstatat64,
    [301] = (syscall_t) sys_unlinkat,
    [302] = (syscall_t) sys_renameat,
    [303] = (syscall_t) sys_linkat,
    [304] = (syscall_t) sys_symlinkat,
    [305] = (syscall_t) sys_readlinkat,
    [306] = (syscall_t) sys_fchmodat,
    [307] = (syscall_t) sys_faccessat,
    [308] = (syscall_t) sys_pselect,
    [309] = (syscall_t) sys_ppoll,
    [311] = (syscall_t) sys_set_robust_list,
    [312] = (syscall_t) sys_get_robust_list,
    [313] = (syscall_t) sys_splice,
    [319] = (syscall_t) sys_epoll_pwait,
    [320] = (syscall_t) sys_utimensat,
    [322] = (syscall_t) sys_timerfd_create,
    [323] = (syscall_t) sys_eventfd,
    [324] = (syscall_t) sys_fallocate,
    [325] = (syscall_t) sys_timerfd_settime,
    [328] = (syscall_t) sys_eventfd2,
    [329] = (syscall_t) sys_epoll_create,
    [330] = (syscall_t) sys_dup3,
    [331] = (syscall_t) sys_pipe2,
    [332] = (syscall_t) syscall_stub, // inotify_init1
    [340] = (syscall_t) sys_prlimit64,
    [345] = (syscall_t) sys_sendmmsg,
    [352] = (syscall_t) syscall_stub, // sched_getattr
    [353] = (syscall_t) sys_renameat2,
    [355] = (syscall_t) sys_getrandom,
    [359] = (syscall_t) sys_socket,
    [360] = (syscall_t) sys_socketpair,
    [361] = (syscall_t) sys_bind,
    [362] = (syscall_t) sys_connect,
    [363] = (syscall_t) sys_listen,
    [364] = (syscall_t) syscall_stub, // accept4
    [365] = (syscall_t) sys_getsockopt,
    [366] = (syscall_t) sys_setsockopt,
    [367] = (syscall_t) sys_getsockname,
    [368] = (syscall_t) sys_getpeername,
    [369] = (syscall_t) sys_sendto,
    [370] = (syscall_t) sys_sendmsg,
    [371] = (syscall_t) sys_recvfrom,
    [372] = (syscall_t) sys_recvmsg,
    [373] = (syscall_t) sys_shutdown,
    [375] = (syscall_t) syscall_silent_stub, // membarrier
    [377] = (syscall_t) sys_copy_file_range,
    [383] = (syscall_t) sys_statx,
    [384] = (syscall_t) sys_arch_prctl,
    [422] = (syscall_t) syscall_silent_stub, // futex_time64
    [439] = (syscall_t) syscall_silent_stub, // faccessat2
};

#define NUM_SYSCALLS (sizeof(syscall_table) / sizeof(syscall_table[0]))

void dump_stack(int lines);

// Map 64-bit syscall numbers to 32-bit syscall numbers
// This is needed because 64-bit programs use different syscall numbers
static unsigned map_64bit_syscall(unsigned syscall_64) {
    // Common 64-bit to 32-bit syscall mappings
    static const unsigned syscall_map[] = {
        [0] = 3,    // sys_read (64-bit #0 -> 32-bit #3)
        [1] = 4,    // sys_write (64-bit #1 -> 32-bit #4)
        [2] = 5,    // sys_open (64-bit #2 -> 32-bit #5)
        [3] = 6,    // sys_close (64-bit #3 -> 32-bit #6)
        [4] = 196,  // sys_lstat (64-bit #4 -> 32-bit #196)
        [5] = 197,  // sys_fstat (64-bit #5 -> 32-bit #197)
        [6] = 195,  // sys_stat (64-bit #6 -> 32-bit #195)
        [7] = 174,  // sys_rt_sigaction (64-bit #7 -> 32-bit #174)
        [8] = 175,  // sys_rt_sigprocmask (64-bit #8 -> 32-bit #175)
        [9] = 19,   // sys_lseek (64-bit #9 -> 32-bit #19)
        [10] = 90,  // sys_mmap (64-bit #10 -> 32-bit #90)
        [11] = 125, // sys_mprotect (64-bit #11 -> 32-bit #125)
        [12] = 91,  // sys_munmap (64-bit #12 -> 32-bit #91)
        [13] = 45,  // sys_brk (64-bit #13 -> 32-bit #45)
        [14] = 176, // sys_rt_sigreturn (64-bit #14 -> 32-bit #176)
        [15] = 54,  // sys_ioctl (64-bit #15 -> 32-bit #54)
        [16] = 141, // sys_pread64 (64-bit #16 -> 32-bit #141)
        [17] = 142, // sys_pwrite64 (64-bit #17 -> 32-bit #142)
        [18] = 145, // sys_readv (64-bit #18 -> 32-bit #145)
        [19] = 146, // sys_writev (64-bit #19 -> 32-bit #146)
        [20] = 33,  // sys_access (64-bit #20 -> 32-bit #33)
        [21] = 42,  // sys_pipe (64-bit #21 -> 32-bit #42)
        [22] = 140, // sys_llseek (64-bit #22 -> 32-bit #140)
        [23] = 143, // sys_pselect6 (64-bit #23 -> 32-bit #143)
        [24] = 282, // sys_ppoll (64-bit #24 -> 32-bit #282)
        [25] = 41,  // sys_dup (64-bit #25 -> 32-bit #41)
        [26] = 63,  // sys_dup2 (64-bit #26 -> 32-bit #63)
        [27] = 29,  // sys_pause (64-bit #27 -> 32-bit #29)
        [28] = 162, // sys_nanosleep (64-bit #28 -> 32-bit #162)
        [29] = 156, // sys_getitimer (64-bit #29 -> 32-bit #156)
        [30] = 27,  // sys_alarm (64-bit #30 -> 32-bit #27)
        [31] = 104, // sys_setitimer (64-bit #31 -> 32-bit #104)
        [32] = 20,  // sys_getpid (64-bit #32 -> 32-bit #20)
        [33] = 147, // sys_sendfile (64-bit #33 -> 32-bit #147)
        [34] = 102, // sys_socket (64-bit #34 -> 32-bit #102)
        [35] = 103, // sys_connect (64-bit #35 -> 32-bit #103)
        [36] = 105, // sys_accept (64-bit #36 -> 32-bit #105)
        [37] = 106, // sys_sendto (64-bit #37 -> 32-bit #106)
        [38] = 107, // sys_recvfrom (64-bit #38 -> 32-bit #107)
        [39] = 108, // sys_sendmsg (64-bit #39 -> 32-bit #108)
        [40] = 109, // sys_recvmsg (64-bit #40 -> 32-bit #109)
        [41] = 110, // sys_shutdown (64-bit #41 -> 32-bit #110)
        [42] = 111, // sys_bind (64-bit #42 -> 32-bit #111)
        [43] = 112, // sys_listen (64-bit #43 -> 32-bit #112)
        [44] = 113, // sys_getsockname (64-bit #44 -> 32-bit #113)
        [45] = 114, // sys_getpeername (64-bit #45 -> 32-bit #114)
        [46] = 115, // sys_socketpair (64-bit #46 -> 32-bit #115)
        [47] = 116, // sys_setsockopt (64-bit #47 -> 32-bit #116)
        [48] = 117, // sys_getsockopt (64-bit #48 -> 32-bit #117)
        [49] = 2,   // sys_fork (64-bit #49 -> 32-bit #2)
        [50] = 2,   // sys_vfork (64-bit #50 -> 32-bit #2, use fork)
        [51] = 11,  // sys_execve (64-bit #51 -> 32-bit #11)
        [52] = 1,   // sys_exit (64-bit #52 -> 32-bit #1)
        [53] = 7,   // sys_wait4 (64-bit #53 -> 32-bit #7)
        [54] = 37,  // sys_kill (64-bit #54 -> 32-bit #37)
        [55] = 109, // sys_uname (64-bit #55 -> 32-bit #109) 
        [56] = 153, // sys_semget (64-bit #56 -> 32-bit #153)
        [57] = 154, // sys_semop (64-bit #57 -> 32-bit #154)
        [58] = 155, // sys_semctl (64-bit #58 -> 32-bit #155)
        [59] = 151, // sys_shmdt (64-bit #59 -> 32-bit #151)
        [60] = 149, // sys_msgget (64-bit #60 -> 32-bit #149)
        [61] = 150, // sys_msgsnd (64-bit #61 -> 32-bit #150)
        [62] = 151, // sys_msgrcv (64-bit #62 -> 32-bit #151)
        [63] = 152, // sys_msgctl (64-bit #63 -> 32-bit #152)
        [64] = 55,  // sys_fcntl (64-bit #64 -> 32-bit #55)
        [65] = 143, // sys_flock (64-bit #65 -> 32-bit #143)
        [66] = 36,  // sys_fsync (64-bit #66 -> 32-bit #36)
        [67] = 148, // sys_fdatasync (64-bit #67 -> 32-bit #148)
        [68] = 84,  // sys_truncate (64-bit #68 -> 32-bit #84)
        [69] = 93,  // sys_ftruncate (64-bit #69 -> 32-bit #93)
        [70] = 220, // sys_getdents (64-bit #70 -> 32-bit #220)
        [71] = 12,  // sys_getcwd (64-bit #71 -> 32-bit #12)
        [72] = 12,  // sys_chdir (64-bit #72 -> 32-bit #12)
        [73] = 94,  // sys_fchdir (64-bit #73 -> 32-bit #94)
        [74] = 38,  // sys_rename (64-bit #74 -> 32-bit #38)
        [75] = 39,  // sys_mkdir (64-bit #75 -> 32-bit #39)
        [76] = 40,  // sys_rmdir (64-bit #76 -> 32-bit #40)
        [77] = 14,  // sys_mknod (64-bit #77 -> 32-bit #14)
        [78] = 9,   // sys_link (64-bit #78 -> 32-bit #9)
        [79] = 10,  // sys_unlink (64-bit #79 -> 32-bit #10)
        [80] = 83,  // sys_symlink (64-bit #80 -> 32-bit #83)
        [81] = 85,  // sys_readlink (64-bit #81 -> 32-bit #85)
        [82] = 15,  // sys_chmod (64-bit #82 -> 32-bit #15)
        [83] = 94,  // sys_fchmod (64-bit #83 -> 32-bit #94)
        [84] = 182, // sys_chown (64-bit #84 -> 32-bit #182)
        [85] = 95,  // sys_fchown (64-bit #85 -> 32-bit #95)
        [86] = 183, // sys_lchown (64-bit #86 -> 32-bit #183)
        [87] = 60,  // sys_umask (64-bit #87 -> 32-bit #60)
        [88] = 78,  // sys_gettimeofday (64-bit #88 -> 32-bit #78)
        [89] = 76,  // sys_getrlimit (64-bit #89 -> 32-bit #76)
        [90] = 77,  // sys_getrusage (64-bit #90 -> 32-bit #77)
        [91] = 116, // sys_sysinfo (64-bit #91 -> 32-bit #116)
        [92] = 43,  // sys_times (64-bit #92 -> 32-bit #43)
        [93] = 26,  // sys_ptrace (64-bit #93 -> 32-bit #26)
        [94] = 24,  // sys_getuid (64-bit #94 -> 32-bit #24)
        [95] = 158, // sys_syslog (64-bit #95 -> 32-bit #158)
        [96] = 47,  // sys_getgid (64-bit #96 -> 32-bit #47)
        [97] = 23,  // sys_setuid (64-bit #97 -> 32-bit #23)
        [98] = 46,  // sys_setgid (64-bit #98 -> 32-bit #46)
        [99] = 49,  // sys_geteuid (64-bit #99 -> 32-bit #49)
        [100] = 50, // sys_getegid (64-bit #100 -> 32-bit #50)
        [101] = 57, // sys_setpgid (64-bit #101 -> 32-bit #57)
        [102] = 64, // sys_getppid (64-bit #102 -> 32-bit #64)
        [103] = 65, // sys_getpgrp (64-bit #103 -> 32-bit #65)
        [104] = 66, // sys_setsid (64-bit #104 -> 32-bit #66)
        [105] = 206, // sys_setreuid (64-bit #105 -> 32-bit #206)
        [106] = 207, // sys_setregid (64-bit #106 -> 32-bit #207)
        [107] = 80, // sys_getgroups (64-bit #107 -> 32-bit #80)
        [108] = 81, // sys_setgroups (64-bit #108 -> 32-bit #81)
        [109] = 208, // sys_setresuid (64-bit #109 -> 32-bit #208)
        [110] = 209, // sys_getresuid (64-bit #110 -> 32-bit #209)
        [111] = 210, // sys_setresgid (64-bit #111 -> 32-bit #210)
        [112] = 211, // sys_getresgid (64-bit #112 -> 32-bit #211)
        [113] = 212, // sys_setfsuid (64-bit #113 -> 32-bit #212)
        [114] = 213, // sys_setfsgid (64-bit #114 -> 32-bit #213)
        [115] = 214, // sys_setsid (64-bit #115 -> 32-bit #214)
        [116] = 215, // sys_setpgid (64-bit #116 -> 32-bit #215)
        [117] = 164, // sys_getpriority (64-bit #117 -> 32-bit #164)
        [118] = 97,  // sys_setpriority (64-bit #118 -> 32-bit #97)
        [119] = 216, // sys_sched_setparam (64-bit #119 -> 32-bit #216)
        [120] = 217, // sys_sched_getparam (64-bit #120 -> 32-bit #217)
        [121] = 218, // sys_sched_setscheduler (64-bit #121 -> 32-bit #218)
        [122] = 219, // sys_sched_getscheduler (64-bit #122 -> 32-bit #219)
        [123] = 220, // sys_sched_get_priority_max (64-bit #123 -> 32-bit #220)
        [124] = 221, // sys_sched_get_priority_min (64-bit #124 -> 32-bit #221)
        [125] = 222, // sys_sched_rr_get_interval (64-bit #125 -> 32-bit #222)
        [126] = 223, // sys_mlock (64-bit #126 -> 32-bit #223)
        [127] = 224, // sys_munlock (64-bit #127 -> 32-bit #224)
        [128] = 225, // sys_mlockall (64-bit #128 -> 32-bit #225)
        [129] = 226, // sys_munlockall (64-bit #129 -> 32-bit #226)
        [130] = 227, // sys_vhangup (64-bit #130 -> 32-bit #227)
        [131] = 228, // sys_modify_ldt (64-bit #131 -> 32-bit #228)
        [132] = 229, // sys_pivot_root (64-bit #132 -> 32-bit #229)
        [133] = 230, // sys_sysctl (64-bit #133 -> 32-bit #230)
        [134] = 231, // sys_prctl (64-bit #134 -> 32-bit #231)
        [135] = 384, // sys_arch_prctl (64-bit #135 -> 32-bit #384)
        [136] = 233, // sys_adjtimex (64-bit #136 -> 32-bit #233)
        [137] = 75,  // sys_setrlimit (64-bit #137 -> 32-bit #75)
        [138] = 61,  // sys_chroot (64-bit #138 -> 32-bit #61)
        [139] = 36,  // sys_sync (64-bit #139 -> 32-bit #36)
        [140] = 148, // sys_acct (64-bit #140 -> 32-bit #148)
        [141] = 79,  // sys_settimeofday (64-bit #141 -> 32-bit #79)
        [142] = 21,  // sys_mount (64-bit #142 -> 32-bit #21)
        [143] = 52,  // sys_umount2 (64-bit #143 -> 32-bit #52)
        [144] = 163, // sys_swapon (64-bit #144 -> 32-bit #163)
        [145] = 115, // sys_swapoff (64-bit #145 -> 32-bit #115)
        [146] = 88,  // sys_reboot (64-bit #146 -> 32-bit #88)
        [147] = 74,  // sys_sethostname (64-bit #147 -> 32-bit #74)
        [148] = 170, // sys_setdomainname (64-bit #148 -> 32-bit #170)
        [149] = 136, // sys_iopl (64-bit #149 -> 32-bit #136)
        [150] = 137, // sys_ioperm (64-bit #150 -> 32-bit #137)
        [151] = 138, // sys_create_module (64-bit #151 -> 32-bit #138)
        [152] = 139, // sys_init_module (64-bit #152 -> 32-bit #139)
        [153] = 140, // sys_delete_module (64-bit #153 -> 32-bit #140)
        [154] = 141, // sys_get_kernel_syms (64-bit #154 -> 32-bit #141)
        [155] = 142, // sys_query_module (64-bit #155 -> 32-bit #142)
        [156] = 143, // sys_quotactl (64-bit #156 -> 32-bit #143)
        [157] = 144, // sys_nfsservctl (64-bit #157 -> 32-bit #144)
        [158] = 145, // sys_getpmsg (64-bit #158 -> 32-bit #145)
        [159] = 146, // sys_putpmsg (64-bit #159 -> 32-bit #146)
        [160] = 147, // sys_afs_syscall (64-bit #160 -> 32-bit #147)
        [161] = 148, // sys_tuxcall (64-bit #161 -> 32-bit #148)
        [162] = 149, // sys_security (64-bit #162 -> 32-bit #149)
        [163] = 150, // sys_gettid (64-bit #163 -> 32-bit #150)
        [164] = 151, // sys_readahead (64-bit #164 -> 32-bit #151)
        [165] = 152, // sys_setxattr (64-bit #165 -> 32-bit #152)
        [166] = 153, // sys_lsetxattr (64-bit #166 -> 32-bit #153)
        [167] = 154, // sys_fsetxattr (64-bit #167 -> 32-bit #154)
        [168] = 155, // sys_getxattr (64-bit #168 -> 32-bit #155)
        [169] = 156, // sys_lgetxattr (64-bit #169 -> 32-bit #156)
        [170] = 157, // sys_fgetxattr (64-bit #170 -> 32-bit #157)
        [171] = 158, // sys_listxattr (64-bit #171 -> 32-bit #158)
        [172] = 159, // sys_llistxattr (64-bit #172 -> 32-bit #159)
        [173] = 160, // sys_flistxattr (64-bit #173 -> 32-bit #160)
        [174] = 161, // sys_removexattr (64-bit #174 -> 32-bit #161)
        [175] = 162, // sys_lremovexattr (64-bit #175 -> 32-bit #162)
        [176] = 163, // sys_fremovexattr (64-bit #176 -> 32-bit #163)
        [177] = 238, // sys_tkill (64-bit #177 -> 32-bit #238)
        [178] = 13,  // sys_time (64-bit #178 -> 32-bit #13)
        [179] = 240, // sys_futex (64-bit #179 -> 32-bit #240)
        [180] = 241, // sys_sched_setaffinity (64-bit #180 -> 32-bit #241)
        [181] = 242, // sys_sched_getaffinity (64-bit #181 -> 32-bit #242)
        [182] = 243, // sys_set_thread_area (64-bit #182 -> 32-bit #243)
        [183] = 244, // sys_io_setup (64-bit #183 -> 32-bit #244)
        [184] = 245, // sys_io_destroy (64-bit #184 -> 32-bit #245)
        [185] = 246, // sys_io_getevents (64-bit #185 -> 32-bit #246)
        [186] = 247, // sys_io_submit (64-bit #186 -> 32-bit #247)
        [187] = 248, // sys_io_cancel (64-bit #187 -> 32-bit #248)
        [188] = 249, // sys_get_thread_area (64-bit #188 -> 32-bit #249)
        [189] = 250, // sys_lookup_dcookie (64-bit #189 -> 32-bit #250)
        [190] = 251, // sys_epoll_create (64-bit #190 -> 32-bit #251)
        [191] = 252, // sys_epoll_ctl_old (64-bit #191 -> 32-bit #252)
        [192] = 253, // sys_epoll_wait_old (64-bit #192 -> 32-bit #253)
        [193] = 254, // sys_remap_file_pages (64-bit #193 -> 32-bit #254)
        [194] = 221, // sys_getdents64 (64-bit #194 -> 32-bit #221)
        [195] = 216, // sys_set_tid_address (64-bit #195 -> 32-bit #216)
        [196] = 217, // sys_restart_syscall (64-bit #196 -> 32-bit #217)
        [197] = 218, // sys_semtimedop (64-bit #197 -> 32-bit #218)
        [198] = 219, // sys_fadvise64 (64-bit #198 -> 32-bit #219)
        [199] = 220, // sys_timer_create (64-bit #199 -> 32-bit #220)
        [200] = 221, // sys_timer_settime (64-bit #200 -> 32-bit #221)
        [201] = 222, // sys_timer_gettime (64-bit #201 -> 32-bit #222)
        [202] = 223, // sys_timer_getoverrun (64-bit #202 -> 32-bit #223)
        [203] = 224, // sys_timer_delete (64-bit #203 -> 32-bit #224)
        [204] = 225, // sys_clock_settime (64-bit #204 -> 32-bit #225)
        [205] = 226, // sys_clock_gettime (64-bit #205 -> 32-bit #226)
        [206] = 227, // sys_clock_getres (64-bit #206 -> 32-bit #227)
        [207] = 228, // sys_clock_nanosleep (64-bit #207 -> 32-bit #228)
        [208] = 229, // sys_exit_group (64-bit #208 -> 32-bit #229)
        [209] = 230, // sys_epoll_wait (64-bit #209 -> 32-bit #230)
        [210] = 231, // sys_epoll_ctl (64-bit #210 -> 32-bit #231)
        [211] = 232, // sys_tgkill (64-bit #211 -> 32-bit #232)
        [212] = 30,  // sys_utime (64-bit #212 -> 32-bit #30)
        [213] = 14,  // sys_mknod (64-bit #213 -> 32-bit #14)
        [214] = 169, // sys_uselib (64-bit #214 -> 32-bit #169)
        [215] = 169, // sys_personality (64-bit #215 -> 32-bit #169)
        [216] = 169, // sys_ustat (64-bit #216 -> 32-bit #169)
        [217] = 99,  // sys_statfs (64-bit #217 -> 32-bit #99)
        [218] = 100, // sys_fstatfs (64-bit #218 -> 32-bit #100)
        [219] = 169, // sys_sysfs (64-bit #219 -> 32-bit #169)
        [220] = 76,  // sys_getpriority (64-bit #220 -> 32-bit #76)
        [221] = 97,  // sys_setpriority (64-bit #221 -> 32-bit #97)
        [222] = 169, // sys_sched_setparam (64-bit #222 -> 32-bit #169)
        [223] = 169, // sys_sched_getparam (64-bit #223 -> 32-bit #169)
        [224] = 169, // sys_sched_setscheduler (64-bit #224 -> 32-bit #169)
        [225] = 169, // sys_sched_getscheduler (64-bit #225 -> 32-bit #169)
        [226] = 169, // sys_sched_get_priority_max (64-bit #226 -> 32-bit #169)
        [227] = 169, // sys_sched_get_priority_min (64-bit #227 -> 32-bit #169)
        [228] = 169, // sys_sched_rr_get_interval (64-bit #228 -> 32-bit #169)
        [229] = 169, // sys_mlock (64-bit #229 -> 32-bit #169)
        [230] = 169, // sys_munlock (64-bit #230 -> 32-bit #169)
        [231] = 169, // sys_mlockall (64-bit #231 -> 32-bit #169)
        [232] = 169, // sys_munlockall (64-bit #232 -> 32-bit #169)
        [233] = 169, // sys_mincore (64-bit #233 -> 32-bit #169)
        [234] = 169, // sys_madvise (64-bit #234 -> 32-bit #169)
        [235] = 169, // sys_readahead (64-bit #235 -> 32-bit #169)
        [236] = 169, // sys_setxattr (64-bit #236 -> 32-bit #169)
        [237] = 169, // sys_lsetxattr (64-bit #237 -> 32-bit #169)
        [238] = 169, // sys_fsetxattr (64-bit #238 -> 32-bit #169)
        [239] = 169, // sys_getxattr (64-bit #239 -> 32-bit #169)
        [240] = 169, // sys_lgetxattr (64-bit #240 -> 32-bit #169)
        [241] = 169, // sys_fgetxattr (64-bit #241 -> 32-bit #169)
        [242] = 169, // sys_listxattr (64-bit #242 -> 32-bit #169)
        [243] = 169, // sys_llistxattr (64-bit #243 -> 32-bit #169)
        [244] = 169, // sys_flistxattr (64-bit #244 -> 32-bit #169)
        [245] = 169, // sys_removexattr (64-bit #245 -> 32-bit #169)
        [246] = 169, // sys_lremovexattr (64-bit #246 -> 32-bit #169)
        [247] = 169, // sys_fremovexattr (64-bit #247 -> 32-bit #169)
        [248] = 169, // sys_tkill (64-bit #248 -> 32-bit #169)
        [249] = 169, // sys_time (64-bit #249 -> 32-bit #169)
        [250] = 169, // sys_futex (64-bit #250 -> 32-bit #169)
        [251] = 169, // sys_sched_setaffinity (64-bit #251 -> 32-bit #169)
        [252] = 169, // sys_sched_getaffinity (64-bit #252 -> 32-bit #169)
        [253] = 169, // sys_set_thread_area (64-bit #253 -> 32-bit #169)
        [254] = 169, // sys_io_setup (64-bit #254 -> 32-bit #169)
        [255] = 169, // sys_io_destroy (64-bit #255 -> 32-bit #169)
        [256] = 169, // sys_io_getevents (64-bit #256 -> 32-bit #169)
        [257] = 169, // sys_io_submit (64-bit #257 -> 32-bit #169)
        [258] = 169, // sys_io_cancel (64-bit #258 -> 32-bit #169)
        [259] = 169, // sys_get_thread_area (64-bit #259 -> 32-bit #169)
        [260] = 169, // sys_lookup_dcookie (64-bit #260 -> 32-bit #169)
        [261] = 169, // sys_epoll_create (64-bit #261 -> 32-bit #169)
        [262] = 169, // sys_epoll_ctl_old (64-bit #262 -> 32-bit #169)
        [263] = 169, // sys_epoll_wait_old (64-bit #263 -> 32-bit #169)
        [264] = 169, // sys_remap_file_pages (64-bit #264 -> 32-bit #169)
        [265] = 169, // sys_getdents64 (64-bit #265 -> 32-bit #169)
        [266] = 169, // sys_set_tid_address (64-bit #266 -> 32-bit #169)
        [267] = 169, // sys_restart_syscall (64-bit #267 -> 32-bit #169)
        [268] = 169, // sys_semtimedop (64-bit #268 -> 32-bit #169)
        [269] = 169, // sys_fadvise64 (64-bit #269 -> 32-bit #169)
        [270] = 169, // sys_timer_create (64-bit #270 -> 32-bit #169)
        [271] = 169, // sys_timer_settime (64-bit #271 -> 32-bit #169)
        [272] = 169, // sys_timer_gettime (64-bit #272 -> 32-bit #169)
        [273] = 169, // sys_timer_getoverrun (64-bit #273 -> 32-bit #169)
        [274] = 169, // sys_timer_delete (64-bit #274 -> 32-bit #169)
        [275] = 169, // sys_clock_settime (64-bit #275 -> 32-bit #169)
        [276] = 169, // sys_clock_gettime (64-bit #276 -> 32-bit #169)
        [277] = 169, // sys_clock_getres (64-bit #277 -> 32-bit #169)
        [278] = 169, // sys_clock_nanosleep (64-bit #278 -> 32-bit #169)
        [279] = 169, // sys_exit_group (64-bit #279 -> 32-bit #169)
        [280] = 169, // sys_epoll_wait (64-bit #280 -> 32-bit #169)
        [281] = 169, // sys_epoll_ctl (64-bit #281 -> 32-bit #169)
        [282] = 169, // sys_tgkill (64-bit #282 -> 32-bit #169)
        [283] = 169, // sys_utimes (64-bit #283 -> 32-bit #169)
        [284] = 169, // sys_mbind (64-bit #284 -> 32-bit #169)
        [285] = 169, // sys_set_mempolicy (64-bit #285 -> 32-bit #169)
        [286] = 169, // sys_get_mempolicy (64-bit #286 -> 32-bit #169)
        [287] = 169, // sys_mq_open (64-bit #287 -> 32-bit #169)
        [288] = 169, // sys_mq_unlink (64-bit #288 -> 32-bit #169)
        [289] = 169, // sys_mq_timedsend (64-bit #289 -> 32-bit #169)
        [290] = 169, // sys_mq_timedreceive (64-bit #290 -> 32-bit #169)
        [291] = 169, // sys_mq_notify (64-bit #291 -> 32-bit #169)
        [292] = 169, // sys_mq_getsetattr (64-bit #292 -> 32-bit #169)
        [293] = 169, // sys_kexec_load (64-bit #293 -> 32-bit #169)
        [294] = 169, // sys_waitid (64-bit #294 -> 32-bit #169)
        [295] = 169, // sys_add_key (64-bit #295 -> 32-bit #169)
        [296] = 169, // sys_request_key (64-bit #296 -> 32-bit #169)
        [297] = 169, // sys_keyctl (64-bit #297 -> 32-bit #169)
        [298] = 169, // sys_ioprio_set (64-bit #298 -> 32-bit #169)
        [299] = 169, // sys_ioprio_get (64-bit #299 -> 32-bit #169)
        [300] = 169, // sys_inotify_init (64-bit #300 -> 32-bit #169)
        [301] = 169, // sys_inotify_add_watch (64-bit #301 -> 32-bit #169)
        [302] = 169, // sys_inotify_rm_watch (64-bit #302 -> 32-bit #169)
        [303] = 169, // sys_migrate_pages (64-bit #303 -> 32-bit #169)
        [304] = 169, // sys_openat (64-bit #304 -> 32-bit #169)
        [305] = 169, // sys_mkdirat (64-bit #305 -> 32-bit #169)
        [306] = 169, // sys_mknodat (64-bit #306 -> 32-bit #169)
        [307] = 169, // sys_fchownat (64-bit #307 -> 32-bit #169)
        [308] = 169, // sys_futimesat (64-bit #308 -> 32-bit #169)
        [309] = 169, // sys_fstatat64 (64-bit #309 -> 32-bit #169)
        [310] = 169, // sys_unlinkat (64-bit #310 -> 32-bit #169)
        [311] = 169, // sys_renameat (64-bit #311 -> 32-bit #169)
        [312] = 169, // sys_linkat (64-bit #312 -> 32-bit #169)
        [313] = 169, // sys_symlinkat (64-bit #313 -> 32-bit #169)
        [314] = 169, // sys_readlinkat (64-bit #314 -> 32-bit #169)
        [315] = 169, // sys_fchmodat (64-bit #315 -> 32-bit #169)
        [316] = 169, // sys_faccessat (64-bit #316 -> 32-bit #169)
        [317] = 169, // sys_pselect6 (64-bit #317 -> 32-bit #169)
        [318] = 169, // sys_ppoll (64-bit #318 -> 32-bit #169)
        [319] = 169, // sys_unshare (64-bit #319 -> 32-bit #169)
        [320] = 169, // sys_set_robust_list (64-bit #320 -> 32-bit #169)
        [321] = 169, // sys_get_robust_list (64-bit #321 -> 32-bit #169)
        [322] = 169, // sys_splice (64-bit #322 -> 32-bit #169)
        [323] = 169, // sys_tee (64-bit #323 -> 32-bit #169)
        [324] = 169, // sys_sync_file_range (64-bit #324 -> 32-bit #169)
        [325] = 169, // sys_vmsplice (64-bit #325 -> 32-bit #169)
        [326] = 169, // sys_move_pages (64-bit #326 -> 32-bit #169)
        [327] = 169, // sys_utimensat (64-bit #327 -> 32-bit #169)
        [328] = 169, // sys_epoll_pwait (64-bit #328 -> 32-bit #169)
        [329] = 169, // sys_signalfd (64-bit #329 -> 32-bit #169)
        [330] = 169, // sys_timerfd_create (64-bit #330 -> 32-bit #169)
        [331] = 169, // sys_eventfd (64-bit #331 -> 32-bit #169)
        [332] = 169, // sys_fallocate (64-bit #332 -> 32-bit #169)
        [333] = 169, // sys_timerfd_settime (64-bit #333 -> 32-bit #169)
        [334] = 169, // sys_timerfd_gettime (64-bit #334 -> 32-bit #169)
        [335] = 169, // sys_accept4 (64-bit #335 -> 32-bit #169)
        [336] = 169, // sys_signalfd4 (64-bit #336 -> 32-bit #169)
        [337] = 169, // sys_eventfd2 (64-bit #337 -> 32-bit #169)
        [338] = 169, // sys_epoll_create1 (64-bit #338 -> 32-bit #169)
        [339] = 169, // sys_dup3 (64-bit #339 -> 32-bit #169)
        [340] = 169, // sys_pipe2 (64-bit #340 -> 32-bit #169)
        [341] = 169, // sys_inotify_init1 (64-bit #341 -> 32-bit #169)
        [342] = 169, // sys_preadv (64-bit #342 -> 32-bit #169)
        [343] = 169, // sys_pwritev (64-bit #343 -> 32-bit #169)
        [344] = 169, // sys_rt_tgsigqueueinfo (64-bit #344 -> 32-bit #169)
        [345] = 169, // sys_perf_event_open (64-bit #345 -> 32-bit #169)
        [346] = 169, // sys_recvmmsg (64-bit #346 -> 32-bit #169)
        [347] = 169, // sys_fanotify_init (64-bit #347 -> 32-bit #169)
        [348] = 169, // sys_fanotify_mark (64-bit #348 -> 32-bit #169)
        [349] = 169, // sys_prlimit64 (64-bit #349 -> 32-bit #169)
        [350] = 169, // sys_name_to_handle_at (64-bit #350 -> 32-bit #169)
        [351] = 169, // sys_open_by_handle_at (64-bit #351 -> 32-bit #169)
        [352] = 169, // sys_clock_adjtime (64-bit #352 -> 32-bit #169)
        [353] = 169, // sys_syncfs (64-bit #353 -> 32-bit #169)
        [354] = 169, // sys_sendmmsg (64-bit #354 -> 32-bit #169)
        [355] = 169, // sys_setns (64-bit #355 -> 32-bit #169)
        [356] = 169, // sys_getcpu (64-bit #356 -> 32-bit #169)
        [357] = 169, // sys_process_vm_readv (64-bit #357 -> 32-bit #169)
        [358] = 169, // sys_process_vm_writev (64-bit #358 -> 32-bit #169)
        [359] = 169, // sys_kcmp (64-bit #359 -> 32-bit #169)
        [360] = 169, // sys_finit_module (64-bit #360 -> 32-bit #169)
        [361] = 169, // sys_sched_setattr (64-bit #361 -> 32-bit #169)
        [362] = 169, // sys_sched_getattr (64-bit #362 -> 32-bit #169)
        [363] = 169, // sys_renameat2 (64-bit #363 -> 32-bit #169)
        [364] = 169, // sys_seccomp (64-bit #364 -> 32-bit #169)
        [365] = 169, // sys_getrandom (64-bit #365 -> 32-bit #169)
        [366] = 169, // sys_memfd_create (64-bit #366 -> 32-bit #169)
        [367] = 169, // sys_kexec_file_load (64-bit #367 -> 32-bit #169)
        [368] = 169, // sys_bpf (64-bit #368 -> 32-bit #169)
        [369] = 169, // sys_execveat (64-bit #369 -> 32-bit #169)
        [370] = 169, // sys_userfaultfd (64-bit #370 -> 32-bit #169)
        [371] = 169, // sys_membarrier (64-bit #371 -> 32-bit #169)
        [372] = 169, // sys_mlock2 (64-bit #372 -> 32-bit #169)
        [373] = 169, // sys_copy_file_range (64-bit #373 -> 32-bit #169)
        [374] = 169, // sys_preadv2 (64-bit #374 -> 32-bit #169)
        [375] = 169, // sys_pwritev2 (64-bit #375 -> 32-bit #169)
        [376] = 169, // sys_pkey_mprotect (64-bit #376 -> 32-bit #169)
        [377] = 169, // sys_pkey_alloc (64-bit #377 -> 32-bit #169)
        [378] = 169, // sys_pkey_free (64-bit #378 -> 32-bit #169)
        [379] = 169, // sys_statx (64-bit #379 -> 32-bit #169)
        [380] = 169, // sys_io_pgetevents (64-bit #380 -> 32-bit #169)
        [381] = 169, // sys_rseq (64-bit #381 -> 32-bit #169)
        [382] = 169, // sys_pidfd_send_signal (64-bit #382 -> 32-bit #169)
        [383] = 169, // sys_io_uring_setup (64-bit #383 -> 32-bit #169)
        [384] = 169, // sys_io_uring_enter (64-bit #384 -> 32-bit #169)
        [385] = 169, // sys_io_uring_register (64-bit #385 -> 32-bit #169)
        [386] = 169, // sys_open_tree (64-bit #386 -> 32-bit #169)
        [387] = 169, // sys_move_mount (64-bit #387 -> 32-bit #169)
        [388] = 169, // sys_fsopen (64-bit #388 -> 32-bit #169)
        [389] = 169, // sys_fsconfig (64-bit #389 -> 32-bit #169)
        [390] = 169, // sys_fsmount (64-bit #390 -> 32-bit #169)
        [391] = 169, // sys_fspick (64-bit #391 -> 32-bit #169)
        [392] = 169, // sys_pidfd_open (64-bit #392 -> 32-bit #169)
        [393] = 169, // sys_clone3 (64-bit #393 -> 32-bit #169)
        [394] = 169, // sys_close_range (64-bit #394 -> 32-bit #169)
        [395] = 169, // sys_openat2 (64-bit #395 -> 32-bit #169)
        [396] = 169, // sys_pidfd_getfd (64-bit #396 -> 32-bit #169)
        [397] = 169, // sys_faccessat2 (64-bit #397 -> 32-bit #169)
        [398] = 169, // sys_process_madvise (64-bit #398 -> 32-bit #169)
        [399] = 169, // sys_epoll_pwait2 (64-bit #399 -> 32-bit #169)
        [400] = 169, // sys_mount_setattr (64-bit #400 -> 32-bit #169)
        [401] = 169, // sys_quotactl_fd (64-bit #401 -> 32-bit #169)
        [402] = 169, // sys_landlock_create_ruleset (64-bit #402 -> 32-bit #169)
        [403] = 169, // sys_landlock_add_rule (64-bit #403 -> 32-bit #169)
        [404] = 169, // sys_landlock_restrict_self (64-bit #404 -> 32-bit #169)
        [405] = 169, // sys_memfd_secret (64-bit #405 -> 32-bit #169)
        [406] = 169, // sys_process_mrelease (64-bit #406 -> 32-bit #169)
        [407] = 169, // sys_futex_waitv (64-bit #407 -> 32-bit #169)
        [408] = 169, // sys_set_mempolicy_home_node (64-bit #408 -> 32-bit #169)
        [409] = 169, // sys_cachestat (64-bit #409 -> 32-bit #169)
        [410] = 169, // sys_fchmodat2 (64-bit #410 -> 32-bit #169)
        [411] = 169, // sys_map_shadow_stack (64-bit #411 -> 32-bit #169)
        [412] = 169, // sys_futex_wake (64-bit #412 -> 32-bit #169)
        [413] = 169, // sys_futex_wait (64-bit #413 -> 32-bit #169)
        [414] = 169, // sys_futex_requeue (64-bit #414 -> 32-bit #169)
        [415] = 169, // sys_statmount (64-bit #415 -> 32-bit #169)
        [416] = 169, // sys_listmount (64-bit #416 -> 32-bit #169)
        [417] = 169, // sys_lsm_get_self_attr (64-bit #417 -> 32-bit #169)
        [418] = 169, // sys_lsm_set_self_attr (64-bit #418 -> 32-bit #169)
        [419] = 169, // sys_lsm_list_modules (64-bit #419 -> 32-bit #169)
        [420] = 169, // sys_mseal (64-bit #420 -> 32-bit #169)
    };
    
    const unsigned map_size = sizeof(syscall_map) / sizeof(syscall_map[0]);
    if (syscall_64 < map_size && syscall_map[syscall_64] != 0) {
        return syscall_map[syscall_64];
    }
    
    return syscall_64; // Return unmapped for unknown syscalls
}

void handle_interrupt(int interrupt) {
    struct cpu_state *cpu = &current->cpu;
    if (interrupt == INT_SYSCALL) {
        unsigned syscall_num = cpu->eax;
        if (syscall_num >= NUM_SYSCALLS || syscall_table[syscall_num] == NULL) {
            printk("%d(%s) missing syscall %d\n", current->pid, current->comm, syscall_num);
            cpu->eax = _ENOSYS;
        } else {
            if (syscall_table[syscall_num] == (syscall_t) syscall_stub) {
                printk("%d(%s) stub syscall %d\n", current->pid, current->comm, syscall_num);
            }
            STRACE("%d call %-3d ", current->pid, syscall_num);
#ifdef ISH_64BIT
            // For 64-bit builds: pass 32-bit register values directly
            // System calls will internally handle address vs non-address parameter types
            int result = syscall_table[syscall_num](
                cpu->ebx, cpu->ecx, cpu->edx,
                cpu->esi, cpu->edi, cpu->ebp);
#else
            int result = syscall_table[syscall_num](cpu->ebx, cpu->ecx, cpu->edx, cpu->esi, cpu->edi, cpu->ebp);
#endif
            STRACE(" = 0x%x\n", result);
            cpu->eax = result;
        }
#ifdef ISH_64BIT
    } else if (interrupt == INT_SYSCALL64) {
        // 64-bit syscall instruction - use proper 64-bit register convention
        unsigned syscall_num = cpu->rax;
        
        // Map 64-bit syscall numbers to 32-bit syscall numbers
        unsigned mapped_syscall = map_64bit_syscall(syscall_num);
        STRACE("%d 64-bit call %-3d (mapped from %d) ", current->pid, mapped_syscall, syscall_num);
        syscall_num = mapped_syscall;
        
        if (syscall_num >= NUM_SYSCALLS || syscall_table[syscall_num] == NULL) {
            printk("%d(%s) missing 64-bit syscall %d\n", current->pid, current->comm, syscall_num);
            cpu->rax = _ENOSYS;
        } else {
            if (syscall_table[syscall_num] == (syscall_t) syscall_stub) {
                printk("%d(%s) stub 64-bit syscall %d\n", current->pid, current->comm, syscall_num);
            }
            // 64-bit syscall uses different register convention:
            // rdi, rsi, rdx, r10, r8, r9 (not ebx, ecx, edx, esi, edi, ebp)
            int result = syscall_table[syscall_num](
                cpu->rdi, cpu->rsi, cpu->rdx,
                cpu->r10, cpu->r8, cpu->r9);
            STRACE(" = 0x%x\n", result);
            cpu->rax = result;
        }
#endif
    } else if (interrupt == INT_GPF) {
        // some page faults, such as stack growing or CoW clones, are handled by mem_ptr
        read_wrlock(&current->mem->lock);
        void *ptr = mem_ptr(current->mem, cpu->segfault_addr, cpu->segfault_was_write ? MEM_WRITE : MEM_READ);
        read_wrunlock(&current->mem->lock);
        if (ptr == NULL) {
#ifdef ISH_64BIT
            printk("%d page fault on 0x%x at 0x%llx\n", current->pid, cpu->segfault_addr, cpu->rip);
#else
            printk("%d page fault on 0x%x at 0x%x\n", current->pid, cpu->segfault_addr, cpu->eip);
#endif
            struct siginfo_ info = {
                .code = mem_segv_reason(current->mem, cpu->segfault_addr),
                .fault.addr = cpu->segfault_addr,
            };
            dump_stack(8);
            deliver_signal(current, SIGSEGV_, info);
        }
    } else if (interrupt == INT_UNDEFINED) {
#ifdef ISH_64BIT
        printk("%d illegal instruction at 0x%llx: ", current->pid, cpu->rip);
        for (int i = 0; i < 8; i++) {
            uint8_t b;
            if (user_get(cpu->rip + i, b))
                break;
#else
        printk("%d illegal instruction at 0x%x: ", current->pid, cpu->eip);
        for (int i = 0; i < 8; i++) {
            uint8_t b;
            if (user_get(cpu->eip + i, b))
                break;
#endif
            printk("%02x ", b);
        }
        printk("\n");
        dump_stack(8);
        struct siginfo_ info = {
            .code = SI_KERNEL_,
#ifdef ISH_64BIT
            .fault.addr = cpu->rip,
#else
            .fault.addr = cpu->eip,
#endif
        };
        deliver_signal(current, SIGILL_, info);
    } else if (interrupt == INT_BREAKPOINT) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = SI_KERNEL_,
        });
        unlock(&pids_lock);
    } else if (interrupt == INT_DEBUG) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = TRAP_TRACE_,
        });
        unlock(&pids_lock);
    } else if (interrupt != INT_TIMER) {
        printk("%d unhandled interrupt %d\n", current->pid, interrupt);
        sys_exit(interrupt);
    }

    receive_signals();
    struct tgroup *group = current->group;
    lock(&group->lock);
    while (group->stopped)
        wait_for_ignore_signals(&group->stopped_cond, &group->lock, NULL);
    unlock(&group->lock);
}

void dump_maps(void) {
    extern void proc_maps_dump(struct task *task, struct proc_data *buf);
    struct proc_data buf = {};
    proc_maps_dump(current, &buf);
    // go a line at a time because it can be fucking enormous
    char *orig_data = buf.data;
    while (buf.size > 0) {
        size_t chunk_size = buf.size;
        if (chunk_size > 1024)
            chunk_size = 1024;
        printk("%.*s", chunk_size, buf.data);
        buf.data += chunk_size;
        buf.size -= chunk_size;
    }
    free(orig_data);
}

void dump_mem(addr_t start, uint_t len) {
    const int width = 8;
    for (addr_t addr = start; addr < start + len; addr += sizeof(dword_t)) {
        unsigned from_left = (addr - start) / sizeof(dword_t) % width;
        if (from_left == 0)
            printk("%08x: ", addr);
        dword_t word;
        if (user_get(addr, word))
            break;
        printk("%08x ", word);
        if (from_left == width - 1)
            printk("\n");
    }
}

void dump_stack(int lines) {
#ifdef ISH_64BIT
    printk("stack at %llx, base at %llx, ip at %llx\n", current->cpu.rsp, current->cpu.rbp, current->cpu.rip);
#else
    printk("stack at %x, base at %x, ip at %x\n", current->cpu.esp, current->cpu.ebp, current->cpu.eip);
#endif
    dump_mem(current->cpu.esp, lines * sizeof(dword_t) * 8);
}

// TODO find a home for this
#ifdef LOG_OVERRIDE
int log_override = 0;
#endif
