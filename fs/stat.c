#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "fs/fd.h"
#include "fs/path.h"

struct newstat64 stat_convert_newstat64(struct statbuf stat) {
    struct newstat64 newstat;
    newstat.dev = stat.dev;
    newstat.fucked_ino = stat.inode;
    newstat.ino = stat.inode;
    newstat.mode = stat.mode;
    newstat.nlink = stat.nlink;
    newstat.uid = stat.uid;
    newstat.gid = stat.gid;
    newstat.rdev = stat.rdev;
    newstat.size = stat.size;
    newstat.blksize = stat.blksize;
    newstat.blocks = stat.blocks;
    newstat.atime = stat.atime;
    newstat.atime_nsec = stat.atime_nsec;
    newstat.mtime = stat.mtime;
    newstat.mtime_nsec = stat.mtime_nsec;
    newstat.ctime = stat.ctime;
    newstat.ctime_nsec = stat.ctime_nsec;
    return newstat;
}

#ifdef ISH_GUEST_64BIT
// Convert internal statbuf to x86_64 stat structure
struct stat_x86_64 stat_convert_x86_64(struct statbuf stat) {
    struct stat_x86_64 s = {0};
    s.dev_64 = stat.dev;
    s.ino_64 = stat.inode;
    s.nlink_64 = stat.nlink;
    s.mode_64 = stat.mode;
    s.uid_64 = stat.uid;
    s.gid_64 = stat.gid;
    s.rdev_64 = stat.rdev;
    s.size_64 = stat.size;
    s.blksize_64 = stat.blksize;
    s.blocks_64 = stat.blocks;
    s.atime_64 = stat.atime;
    s.atime_nsec_64 = stat.atime_nsec;
    s.mtime_64 = stat.mtime;
    s.mtime_nsec_64 = stat.mtime_nsec;
    s.ctime_64 = stat.ctime;
    s.ctime_nsec_64 = stat.ctime_nsec;
    return s;
}
#endif

int generic_statat(struct fd *at, const char *path_raw, struct statbuf *stat, bool follow_links) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, follow_links ? N_SYMLINK_FOLLOW : N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    memset(stat, 0, sizeof(*stat));
    err = mount->fs->stat(mount, path, stat);
    mount_release(mount);
    return err;
}

// TODO get rid of this and maybe everything else in the file
static struct fd *at_fd(fd_t f) {
    if (f == AT_FDCWD_)
        return AT_PWD;
    return f_get(f);
}

static dword_t sys_stat_path(fd_t at_f, addr_t path_addr, addr_t statbuf_addr, bool follow_links) {
    int err;
    char path[MAX_PATH];
    if (user_read_string(path_addr, path, sizeof(path)))
        return _EFAULT;
    fprintf(stderr, "STAT: at=%d path_addr=0x%llx path=\"%s\" follow=%d\n", at_f, (unsigned long long)path_addr, path, follow_links);
    STRACE("stat(at=%d, path_addr=0x%llx, path=\"%s\", statbuf=0x%x, follow_links=%d)", at_f, (unsigned long long)path_addr, path, statbuf_addr, follow_links);
    struct fd *at = at_fd(at_f);
    if (at == NULL)
        return _EBADF;
    struct statbuf stat = {};
    if ((err = generic_statat(at, path, &stat, follow_links)) < 0)
        return err;
#ifdef ISH_GUEST_64BIT
    struct stat_x86_64 s64 = stat_convert_x86_64(stat);
    if (user_put(statbuf_addr, s64))
        return _EFAULT;
#else
    struct newstat64 newstat = stat_convert_newstat64(stat);
    if (user_put(statbuf_addr, newstat))
        return _EFAULT;
#endif
    return 0;
}

dword_t sys_stat64(addr_t path_addr, addr_t statbuf_addr) {
    return sys_stat_path(AT_FDCWD_, path_addr, statbuf_addr, true);
}

dword_t sys_lstat64(addr_t path_addr, addr_t statbuf_addr) {
    return sys_stat_path(AT_FDCWD_, path_addr, statbuf_addr, false);
}

dword_t sys_fstatat64(fd_t at, addr_t path_addr, addr_t statbuf_addr, dword_t flags) {
    return sys_stat_path(at, path_addr, statbuf_addr, !(flags & AT_SYMLINK_NOFOLLOW_));
}

dword_t sys_fstat64(fd_t fd_no, addr_t statbuf_addr) {
    STRACE("fstat64(%d, 0x%x)", fd_no, statbuf_addr);
    struct fd *fd = f_get(fd_no);
    if (fd == NULL)
        return _EBADF;
    struct statbuf stat = {};
    int err = fd->mount->fs->fstat(fd, &stat);
    if (err < 0)
        return err;
#ifdef ISH_GUEST_64BIT
    struct stat_x86_64 s64 = stat_convert_x86_64(stat);
    if (user_put(statbuf_addr, s64))
        return _EFAULT;
#else
    struct newstat64 newstat = stat_convert_newstat64(stat);
    if (user_put(statbuf_addr, newstat))
        return _EFAULT;
#endif
    return 0;
}

dword_t sys_statx(fd_t at_f, addr_t path_addr, int_t flags, uint_t mask, addr_t statx_addr) {
    int err;
    char path[MAX_PATH];
    if (user_read_string(path_addr, path, sizeof(path)))
        return _EFAULT;
    struct fd *at = at_fd(at_f);
    if (at == NULL)
        return _EBADF;

    STRACE("statx(at=%d, path=\"%s\", flags=%d, mask=%d, statx=0x%x)", at_f, path, flags, mask, statx_addr);

    struct statbuf stat = {};

    if ((flags & AT_EMPTY_PATH_) && strcmp(path, "") == 0) {
        struct fd *fd = at;
        int err = fd->mount->fs->fstat(fd, &stat);
        if (err < 0)
            return err;
    } else {
        bool follow_links = !(flags & AT_SYMLINK_NOFOLLOW_);
        int err = generic_statat(at, path, &stat, follow_links);
        if (err < 0)
            return err;
    }

    // for now, ignore the requested mask and just fill in the same fields as stat returns
    struct statx_ statx = {};
    statx.mask = STATX_BASIC_STATS_;
    statx.blksize = stat.blksize;
    statx.nlink = stat.nlink;
    statx.uid = stat.uid;
    statx.gid = stat.gid;
    statx.mode = stat.mode;
    statx.ino = stat.inode;
    statx.size = stat.size;
    statx.blocks = stat.blocks;
    statx.atime.sec = stat.atime;
    statx.atime.nsec = stat.atime_nsec;
    statx.mtime.sec = stat.mtime;
    statx.mtime.nsec = stat.mtime_nsec;
    statx.ctime.sec = stat.ctime;
    statx.ctime.nsec = stat.ctime_nsec;
    statx.rdev_major = dev_major(stat.rdev);
    statx.rdev_minor = dev_minor(stat.rdev);
    statx.dev_major = dev_major(stat.dev);
    statx.dev_minor = dev_minor(stat.dev);

    if (user_put(statx_addr, statx))
        return _EFAULT;
    return 0;
}
