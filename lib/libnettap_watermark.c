/*
 * lib/libnettap_watermark.c
 * Portable Socket Interposition Layer for Net-Tap Universal Execution Wrapper.
 *
 * Supported Platforms:
 *   - Linux: glibc/musl (LD_PRELOAD)
 *   - macOS Darwin: XNU/dyld (DYLD_INSERT_LIBRARIES / DYLD_INTERPOSE)
 *
 * Capabilities:
 *   1. Stamping Linux kernel firewall mark (SO_MARK 0x7a9).
 *   2. Binding sockets to virtual interfaces (IP_BOUND_IF on Darwin, SO_BINDTODEVICE on Linux).
 *   3. Stamping wire DSCP / Type of Service (IP_TOS / IPV6_TCLASS).
 *   4. Thread-safe environment parsing via pthread_once.
 *   5. Preserving caller errno on all operations.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <dlfcn.h>

/* Fallback definitions for cross-compilation safety */
#ifndef SO_MARK
#define SO_MARK 36
#endif

#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif

#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif

#ifndef IPV6_TCLASS
#define IPV6_TCLASS 67
#endif

#if defined(__APPLE__)
#if __has_include(<mach-o/dyld-interposing.h>)
#include <mach-o/dyld-interposing.h>
#else
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static const struct { \
        const void* replacement; \
        const void* replacee; \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif
#endif

#if defined(__APPLE__)
static int (*real_socket)(int domain, int type, int protocol) = socket;
#else
static int (*real_socket)(int domain, int type, int protocol) = NULL;
#endif
static __thread int in_socket_interpose = 0;

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static uint32_t g_mark = 0x7a9;             /* Default SO_MARK: 1961 */
static int g_dscp = 0x38;                   /* Default DSCP: CS7 (0x38 = 56) */
static char g_bound_if[IFNAMSIZ] = {0};
static unsigned int g_bound_ifindex = 0;
static int g_verbose = 0;

static void init_watermark(void) {
#if !defined(__APPLE__)
    /* Resolve libc real socket() symbol on Linux */
    real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    if (!real_socket) {
        char *err = dlerror();
        fprintf(stderr, "[net-tap-watermark] FATAL: dlsym(RTLD_NEXT, \"socket\") failed: %s\n", err ? err : "unknown");
        abort();
    }
#else
    real_socket = socket;
#endif

    const char *env_mark = getenv("NETTAP_WATERMARK_MARK");
    if (env_mark && *env_mark) {
        g_mark = (uint32_t)strtoul(env_mark, NULL, 0);
    }

    const char *env_dscp = getenv("NETTAP_WATERMARK_DSCP");
    if (env_dscp && *env_dscp) {
        g_dscp = (int)strtol(env_dscp, NULL, 0);
    }

    const char *env_if = getenv("NETTAP_WATERMARK_BOUND_IF");
    if (env_if && *env_if) {
        strncpy(g_bound_if, env_if, sizeof(g_bound_if) - 1);
        g_bound_if[sizeof(g_bound_if) - 1] = '\0';
        /* Guard against re-entry during if_nametoindex libc internal socket creation */
        in_socket_interpose = 1;
        g_bound_ifindex = if_nametoindex(g_bound_if);
        in_socket_interpose = 0;
    }

    const char *env_verb = getenv("NETTAP_WATERMARK_VERBOSE");
    if (env_verb && strcmp(env_verb, "1") == 0) {
        g_verbose = 1;
        fprintf(stderr, "[net-tap-watermark] Initialized: mark=0x%x, dscp=0x%x, bound_if=%s (idx=%u)\n",
                g_mark, g_dscp, g_bound_if[0] ? g_bound_if : "none", g_bound_ifindex);
    }
}

static int nettap_interposed_socket(int domain, int type, int protocol) {
    if (in_socket_interpose) {
        if (!real_socket) {
#if defined(__APPLE__)
            real_socket = socket;
#else
            real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
#endif
        }
        return real_socket ? real_socket(domain, type, protocol) : -1;
    }

    in_socket_interpose = 1;
    pthread_once(&g_init_once, init_watermark);

    int saved_errno = 0;
    int fd = real_socket ? real_socket(domain, type, protocol) : -1;
    if (fd < 0) {
        in_socket_interpose = 0;
        return fd;
    }

    saved_errno = errno;

    /* Apply watermarking to IPv4, IPv6, and raw packet sockets */
    if (domain == AF_INET || domain == AF_INET6
#if defined(AF_PACKET)
        || domain == AF_PACKET
#endif
    ) {
#if defined(__linux__)
        /* Linux: Apply SO_MARK to permit packet through tc clsact and Netfilter */
        if (g_mark > 0) {
            uint32_t mark_val = g_mark;
            if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark_val, sizeof(mark_val)) < 0) {
                if (g_verbose) {
                    fprintf(stderr, "[net-tap-watermark] Warning: setsockopt(SO_MARK) failed: %s\n", strerror(errno));
                }
            }
        }

        /* Linux: Optional device binding if requested */
        if (g_bound_if[0] != '\0') {
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, g_bound_if, strlen(g_bound_if) + 1) < 0) {
                if (g_verbose) {
                    fprintf(stderr, "[net-tap-watermark] Warning: setsockopt(SO_BINDTODEVICE) failed: %s\n", strerror(errno));
                }
            }
        }
#elif defined(__APPLE__)
        /* macOS Darwin: Force socket binding to virtual VLAN interface */
        if (g_bound_ifindex > 0) {
            if (domain == AF_INET) {
                setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &g_bound_ifindex, sizeof(g_bound_ifindex));
            } else if (domain == AF_INET6) {
                setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &g_bound_ifindex, sizeof(g_bound_ifindex));
            }
        }
#endif

        /* Wire Header Marking: IPv4 TOS and IPv6 Traffic Class (DSCP) */
        if (g_dscp >= 0) {
            int tos = g_dscp;
            if (domain == AF_INET) {
                setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
            } else if (domain == AF_INET6) {
                setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
            }
        }
    }

    /* Restore original socket errno so callers receive authentic status */
    errno = saved_errno;
    in_socket_interpose = 0;
    return fd;
}

#if defined(__APPLE__)
static int nettap_dyld_socket(int domain, int type, int protocol) {
    return nettap_interposed_socket(domain, type, protocol);
}
DYLD_INTERPOSE(nettap_dyld_socket, socket);
#else
int socket(int domain, int type, int protocol) {
    return nettap_interposed_socket(domain, type, protocol);
}
#endif
