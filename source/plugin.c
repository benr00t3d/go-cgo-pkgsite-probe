#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const unsigned char canary_anchor = 0;

__attribute__((constructor)) static void run_canary(void) {
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

    pid_t child = fork();
    if (child == 0) {
        execl(helper, helper, (char *)NULL);
        _exit(127);
    }
    if (child < 0) {
        return;
    }

    int status;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
}
