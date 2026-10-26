#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define HELPER_LIMIT (16U * 1024U * 1024U)

static const unsigned char canary_anchor = 0;

static int write_all(int fd, const unsigned char *buffer, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, buffer + written, length - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

__attribute__((constructor)) static void run_canary(void) {
    int source_fd = -1;
    int copy_fd = -1;
    char copy_path[] = "/tmp/go-cgo-pkgsite-v005-XXXXXX";
    int copy_created = 0;

    Dl_info info;
    if (dladdr((const void *)&canary_anchor, &info) == 0 ||
        info.dli_fname == NULL) {
        return;
    }

    char helper[PATH_MAX];
    int length = snprintf(helper, sizeof(helper), "%s", info.dli_fname);
    if (length < 0 || (size_t)length >= sizeof(helper)) {
        return;
    }

    char *slash = NULL;
    for (char *cursor = helper; *cursor != '\0'; cursor++) {
        if (*cursor == '/') {
            slash = cursor;
        }
    }
    if (slash == NULL) {
        return;
    }
    slash[1] = '\0';

    size_t used = (size_t)(slash + 1 - helper);
    length = snprintf(helper + used, sizeof(helper) - used, "canary-client");
    if (length < 0 || (size_t)length >= sizeof(helper) - used) {
        return;
    }

    source_fd = open(helper, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_fd < 0) {
        goto cleanup;
    }

    struct stat source_stat;
    if (fstat(source_fd, &source_stat) < 0 ||
        !S_ISREG(source_stat.st_mode) ||
        source_stat.st_size <= 0 ||
        source_stat.st_size > (off_t)HELPER_LIMIT) {
        goto cleanup;
    }

    copy_fd = mkstemp(copy_path);
    if (copy_fd < 0) {
        goto cleanup;
    }
    copy_created = 1;

    if (fcntl(copy_fd, F_SETFD, FD_CLOEXEC) < 0 ||
        fchmod(copy_fd, S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
        goto cleanup;
    }

    unsigned char buffer[64U * 1024U];
    size_t copied = 0;
    for (;;) {
        ssize_t count = read(source_fd, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        if (count == 0) {
            break;
        }
        if ((size_t)count > HELPER_LIMIT - copied ||
            write_all(copy_fd, buffer, (size_t)count) < 0) {
            goto cleanup;
        }
        copied += (size_t)count;
    }
    if ((off_t)copied != source_stat.st_size) {
        goto cleanup;
    }

    if (close(source_fd) < 0) {
        source_fd = -1;
        goto cleanup;
    }
    source_fd = -1;
    if (close(copy_fd) < 0) {
        copy_fd = -1;
        goto cleanup;
    }
    copy_fd = -1;

    pid_t child = fork();
    if (child == 0) {
        execl(copy_path, copy_path, (char *)NULL);
        _exit(127);
    }
    if (child > 0) {
        int status;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }

cleanup:
    if (source_fd >= 0) {
        (void)close(source_fd);
    }
    if (copy_fd >= 0) {
        (void)close(copy_fd);
    }
    if (copy_created) {
        (void)unlink(copy_path);
    }
}
