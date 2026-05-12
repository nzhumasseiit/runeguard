#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

typedef int (*orig_open_t)(const char *pathname, int flags, ...);
typedef int (*orig_openat_t)(int dirfd, const char *pathname, int flags, ...);
typedef int (*orig_execve_t)(const char *filename, char *const argv[], char *const envp[]);
typedef int (*orig_connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

static orig_open_t real_open = NULL;
static orig_openat_t real_openat = NULL;
static orig_execve_t real_execve = NULL;
static orig_connect_t real_connect = NULL;

static void resolve_symbols(void) {
    if (!real_open) real_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
    if (!real_openat) real_openat = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
    if (!real_execve) real_execve = (orig_execve_t)dlsym(RTLD_NEXT, "execve");
    if (!real_connect) real_connect = (orig_connect_t)dlsym(RTLD_NEXT, "connect");
}

__attribute__((constructor))
static void init_shim(void) {
    resolve_symbols();
    fprintf(stderr, "[RuneGuard] LD_PRELOAD shim loaded\n");
}

static int fail_closed(void) {
    const char *value = getenv("RUNEGUARD_FAIL_CLOSED");
    return !value || strcmp(value, "0") != 0;
}

static int fallback_policy(const char *tool, const char *target) {
    if (!target) return 1;

    if (strstr(target, ".env") || strstr(target, "/.ssh/") || strstr(target, "secrets/")) {
        fprintf(stderr, "[RuneGuard BLOCK fallback] %s(%s)\n", tool, target);
        return 0;
    }

    if (strstr(target, "rm -rf") || strstr(target, "curl ") || strstr(target, " nc ") || strstr(target, " scp ")) {
        fprintf(stderr, "[RuneGuard BLOCK fallback] %s(%s)\n", tool, target);
        return 0;
    }

    return 1;
}

static int daemon_allows(const char *json) {
    const char *socket_path = getenv("RUNEGUARD_SOCKET");
    if (!socket_path || socket_path[0] == '\0') return -1;
    resolve_symbols();

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (real_connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (write(fd, json, strlen(json)) < 0) {
        close(fd);
        return -1;
    }

    char response[512] = {0};
    ssize_t read_count = read(fd, response, sizeof(response) - 1);
    close(fd);

    if (read_count <= 0) return -1;
    if (strstr(response, "\"allow\": true") || strstr(response, "\"type\": \"ALLOW\"")) return 1;
    if (strstr(response, "\"allow\": false") || strstr(response, "\"type\": \"BLOCK\"")) return 0;

    return -1;
}

static void json_escape(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input && input[i] && j + 2 < output_size; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
}

static int check_policy(const char *tool, const char *key, const char *target) {
    char escaped[2048] = {0};
    char request[2300] = {0};

    json_escape(target, escaped, sizeof(escaped));
    snprintf(request, sizeof(request), "{\"tool_name\":\"%s\",\"%s\":\"%s\"}", tool, key, escaped);

    int daemon_result = daemon_allows(request);
    if (daemon_result >= 0) {
        if (!daemon_result) {
            fprintf(stderr, "[RuneGuard BLOCK] %s(%s)\n", tool, target);
        }
        return daemon_result;
    }

    if (!fail_closed()) return fallback_policy(tool, target);

    fprintf(stderr, "[RuneGuard BLOCK] daemon unavailable for %s(%s)\n", tool, target);
    return 0;
}

static void argv_to_command(char *const argv[], char *buffer, size_t size) {
    buffer[0] = '\0';
    for (int i = 0; argv && argv[i] && i < 64; i++) {
        if (i > 0) strncat(buffer, " ", size - strlen(buffer) - 1);
        strncat(buffer, argv[i], size - strlen(buffer) - 1);
    }
}

int open(const char *pathname, int flags, ...) {
    resolve_symbols();
    if (!check_policy("open", "pathname", pathname)) {
        errno = EACCES;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return real_open(pathname, flags, mode);
    }

    return real_open(pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    resolve_symbols();
    if (!check_policy("openat", "pathname", pathname)) {
        errno = EACCES;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    }

    return real_openat(dirfd, pathname, flags);
}

int execve(const char *filename, char *const argv[], char *const envp[]) {
    resolve_symbols();
    char command[2048] = {0};
    argv_to_command(argv, command, sizeof(command));

    if (!check_policy("execve", "command", command[0] ? command : filename)) {
        errno = EACCES;
        return -1;
    }

    return real_execve(filename, argv, envp);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    resolve_symbols();

    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));

        if (!check_policy("connect", "host", ip)) {
            errno = EACCES;
            return -1;
        }
    }

    return real_connect(sockfd, addr, addrlen);
}
