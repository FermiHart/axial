/* Private fixture-store descriptor checks. No installed API or wire format. */
#ifndef AXI_LOCAL_STORE_V1_H
#define AXI_LOCAL_STORE_V1_H

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static inline int axi_local_store_directory_fd(int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid()
            || (st.st_mode & 0777) != 0700) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static inline int axi_local_store_open(const char *path)
{
    int fd, saved;
    if (!path || !*path) { errno = EINVAL; return -1; }
    fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (axi_local_store_directory_fd(fd) == 0) return fd;
    saved = errno; (void)close(fd); errno = saved;
    return -1;
}

static inline int axi_local_store_open_directory_at(int dirfd, const char *name)
{
    int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved;
    if (fd < 0) return -1;
    if (axi_local_store_directory_fd(fd) == 0) return fd;
    saved = errno; (void)close(fd); errno = saved;
    return -1;
}

static inline int axi_local_store_open_file_at(int dirfd, const char *name, int flags)
{
    struct stat st;
    int fd, saved;
    /* Never truncate before checking the actual opened inode. NONBLOCK
     * prevents FIFO opens from defeating a bounded owner call. */
    fd = openat(dirfd, name, (flags & ~O_TRUNC) | O_NOFOLLOW | O_CLOEXEC
                            | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0) goto bad;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1
            || (st.st_mode & 077) != 0) {
        errno = EACCES;
        goto bad;
    }
    if ((flags & O_TRUNC) && ftruncate(fd, 0) != 0) goto bad;
    return fd;
bad:
    saved = errno; (void)close(fd); errno = saved;
    return -1;
}

#endif
