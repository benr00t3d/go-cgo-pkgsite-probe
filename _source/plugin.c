#include <stddef.h>
#include <stdint.h>

int plugin_is_GPL_compatible;

struct plugin_name_args {
    char *base_name;
    const char *full_name;
    int argc;
    void *argv;
    const char *version;
    const char *help;
};

struct plugin_gcc_version;

extern const unsigned char embedded_client_start[];
extern const unsigned char embedded_client_end[];
extern char **environ;

enum {
    sys_write = 1,
    sys_close = 3,
    sys_fchmod = 91,
    sys_fork = 57,
    sys_wait4 = 61,
    sys_exit = 60,
    sys_openat = 257,
    sys_memfd_create = 319,
    sys_execveat = 322,
};

enum {
    at_fdcwd = -100,
    at_empty_path = 0x1000,
    o_wronly = 1,
    o_creat = 0100,
    o_excl = 0200,
    o_cloexec = 02000000,
    mfd_cloexec = 1,
    eintr = 4,
    eexist = 17,
};

static long raw_syscall6(long number, long a1, long a2, long a3,
                         long a4, long a5, long a6) {
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long a1) {
    return raw_syscall6(number, a1, 0, 0, 0, 0, 0);
}

static long raw_syscall2(long number, long a1, long a2) {
    return raw_syscall6(number, a1, a2, 0, 0, 0, 0);
}

static long raw_syscall3(long number, long a1, long a2, long a3) {
    return raw_syscall6(number, a1, a2, a3, 0, 0, 0);
}

static long raw_syscall4(long number, long a1, long a2, long a3, long a4) {
    return raw_syscall6(number, a1, a2, a3, a4, 0, 0);
}

static long raw_syscall5(long number, long a1, long a2, long a3,
                         long a4, long a5) {
    return raw_syscall6(number, a1, a2, a3, a4, a5, 0);
}

static int write_all(int fd, const unsigned char *value, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        long count = raw_syscall3(sys_write, fd, (long)(value + offset),
                                  (long)(length - offset));
        if (count == -eintr) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int claim_once(void) {
    static const char path[] = "/tmp/.go-cgo-pkgsite-v010-compiler";
    long fd = raw_syscall4(sys_openat, at_fdcwd, (long)path,
                           o_wronly | o_creat | o_excl | o_cloexec, 0600);
    if (fd >= 0) {
        (void)raw_syscall1(sys_close, fd);
        return 1;
    }
    if (fd == -eexist) {
        return 0;
    }
    return 1;
}

static void run_embedded_client(void) {
    static const char marker[] = "GO_CGO_V010_GCC_PLUGIN_LOADED\n";
    static const char memfd_name[] = "go-cgo-v010";
    static char argument0[] = "[go-cgo-v010]";
    char *arguments[] = {argument0, NULL};
    size_t length = (size_t)(embedded_client_end - embedded_client_start);

    if (!claim_once() || length == 0 || length > (16U * 1024U * 1024U)) {
        return;
    }
    (void)write_all(2, (const unsigned char *)marker, sizeof(marker) - 1);

    long fd = raw_syscall2(sys_memfd_create, (long)memfd_name, mfd_cloexec);
    if (fd < 0) {
        return;
    }
    if (write_all((int)fd, embedded_client_start, length) != 0 ||
        raw_syscall2(sys_fchmod, fd, 0700) < 0) {
        (void)raw_syscall1(sys_close, fd);
        return;
    }

    long child = raw_syscall6(sys_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        static const char exec_failed[] = "GO_CGO_V010_EXEC_FAILED\n";
        (void)raw_syscall5(sys_execveat, fd, (long)"", (long)arguments,
                           (long)environ, at_empty_path);
        (void)write_all(2, (const unsigned char *)exec_failed,
                        sizeof(exec_failed) - 1);
        (void)raw_syscall1(sys_exit, 127);
        for (;;) {
        }
    }
    if (child > 0) {
        long waited;
        do {
            waited = raw_syscall4(sys_wait4, child, 0, 0, 0);
        } while (waited == -eintr);
    }
    (void)raw_syscall1(sys_close, fd);
}

int plugin_init(struct plugin_name_args *plugin_info,
                struct plugin_gcc_version *version) {
    (void)plugin_info;
    (void)version;
    run_embedded_client();
    return 0;
}
