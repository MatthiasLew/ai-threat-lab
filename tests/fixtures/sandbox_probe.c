/* Fixed Linux test payload. It only touches synthetic paths and loopback. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int denied(const char *path, int flags) {
    int fd = open(path, flags, 0600);
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return errno == ENOENT || errno == EROFS || errno == EACCES || errno == EPERM;
}

static int filesystem(const char *canary) {
    int fd = open("/input/zażółć input", O_RDONLY);
    char content = 0;
    if (fd < 0 || read(fd, &content, 1) != 1 || content != 'x') return 11;
    close(fd);
    fd = open("/scratch/probe", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "x", 1) != 1 || unlink("/scratch/probe")) return 12;
    close(fd);
    if (!denied("/input/zażółć input", O_WRONLY | O_TRUNC)) return 13;
    if (!denied(canary, O_RDONLY) || !denied(canary, O_WRONLY)) return 14;
    if (!denied("/input/outside", O_RDONLY)) return 15;
    if (!denied("/outside-scratch", O_WRONLY | O_CREAT)) return 16;
    return 0;
}

static int network_denied(int family, int type, int port) {
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(port)};
    struct sockaddr_in6 v6 = {
        .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT
    };
    v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const struct sockaddr *address = family == AF_INET
        ? (const struct sockaddr *)&v4 : (const struct sockaddr *)&v6;
    socklen_t length = family == AF_INET ? sizeof(v4) : sizeof(v6);
    /* A DNS A query for the reserved name "x.test", sent only to the test listener. */
    const unsigned char query[] = {
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1
    };
    int fd = socket(family, type, 0);
    if (fd < 0) return errno == EAFNOSUPPORT || errno == EACCES || errno == EPERM;
    int result = type == SOCK_STREAM
        ? connect(fd, address, length) : (int)sendto(fd, query, sizeof(query), 0, address, length);
    int error = errno;
    close(fd);
    return result < 0 && (error == ENETUNREACH || error == EHOSTUNREACH
        || error == EADDRNOTAVAIL || error == ECONNREFUSED || error == EACCES || error == EPERM);
}

static int boundaries(char **argv) {
    int result = filesystem(argv[2]);
    if (result) return result;
    if (getenv("THREAT_LAB_PROBE_SECRET") || fcntl(atoi(argv[3]), F_GETFD) != -1
            || errno != EBADF) return 17;
    if (!network_denied(AF_INET, SOCK_STREAM, atoi(argv[4]))) return 18;
    if (!network_denied(AF_INET6, SOCK_STREAM, atoi(argv[5]))) return 19;
    if (!network_denied(AF_INET, SOCK_DGRAM, atoi(argv[6]))) return 20;
    if (!network_denied(AF_INET6, SOCK_DGRAM, atoi(argv[7]))) return 21;
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || strcmp(tmpdir, "/scratch")) return 22;
    if (socket(AF_UNIX, SOCK_STREAM, 0) != -1 || errno != EPERM) return 23;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "ready")) {
        return socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EPERM ? 0 : 26;
    }
    if (argc == 2 && !strcmp(argv[1], "scratch")) {
        int fd = open("/scratch/partial", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || write(fd, "partial", 7) != 7) return 24;
        return posix_fallocate(fd, 0, 2 * 1024 * 1024) == ENOSPC ? 0 : 25;
    }
    if (argc == 2 && !strcmp(argv[1], "wait")) {
        pid_t child = fork();
        if (child == -1) return 30;
        if (child == 0) {
            if (write(STDOUT_FILENO, "R", 1) != 1) _exit(31);
            sleep(20);
            _exit(32);
        }
        return waitpid(child, NULL, 0) == child ? 0 : 33;
    }
    if (argc == 2 && !strcmp(argv[1], "memory")) {
        const rlim_t ceiling = 64 * 1024 * 1024;
        struct rlimit limit = {ceiling, ceiling};
        if (setrlimit(RLIMIT_AS, &limit)) return 40;
        void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED || munmap(page, 4096)) return 41;
        void *too_large = mmap(NULL, ceiling + 1, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return too_large == MAP_FAILED && errno == ENOMEM ? 0 : 42;
    }
    if (argc != 8 || strcmp(argv[1], "boundaries")) return 50;
    int result = boundaries(argv);
    if (result) return result;
    pid_t child = fork();
    if (child == -1) return 51;
    if (child == 0) _exit(boundaries(argv));
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 52;
    return WEXITSTATUS(status);
}
