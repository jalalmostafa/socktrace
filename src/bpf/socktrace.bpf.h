#ifndef SOCKTRACE_BPF_H
#define SOCKTRACE_BPF_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define SOCKTRACE_NFDBITS (8 * sizeof(unsigned long))
#define SOCKTRACE_NFDBITS_MASK (SOCKTRACE_NFDBITS - 1)
#define SOCKTRACE_LENGTH (1024 / SOCKTRACE_NFDBITS)

#define MAX_PROCESSES 256
#define MAX_SOCKETS SOCKTRACE_NFDBITS

enum socktrace_syscall {
    SOCKTRACE_SYSCALL_SOCKET,
    SOCKTRACE_SYSCALL_BIND,
    SOCKTRACE_SYSCALL_LISTEN,
    SOCKTRACE_SYSCALL_CONNECT,
    SOCKTRACE_SYSCALL_ACCEPT,
    SOCKTRACE_SYSCALL_ACCEPT4,
    SOCKTRACE_SYSCALL_RECVFROM,
    SOCKTRACE_SYSCALL_RECVMSG,
    SOCKTRACE_SYSCALL_RECVMMSG,
    SOCKTRACE_SYSCALL_SENDTO,
    SOCKTRACE_SYSCALL_SENDMSG,
    SOCKTRACE_SYSCALL_SENDMMSG,
    SOCKTRACE_SYSCALL_SETSOCKOPT,
    SOCKTRACE_SYSCALL_GETSOCKOPT,
    SOCKTRACE_SYSCALL_GETPEERNAME,
    SOCKTRACE_SYSCALL_GETSOCKNAME,
    SOCKTRACE_SYSCALL_SHUTDOWN,
    SOCKTRACE_SYSCALL_READ,
    SOCKTRACE_SYSCALL_READV,
    SOCKTRACE_SYSCALL_WRITE,
    SOCKTRACE_SYSCALL_WRITEV,
    SOCKTRACE_SYSCALL_CLOSE,
    SOCKTRACE_SYSCALL_POLL,
    SOCKTRACE_SYSCALL_PPOLL,
    SOCKTRACE_SYSCALL_SELECT,
    SOCKTRACE_SYSCALL_PSELECT,
    SOCKTRACE_SYSCALL_EPOLL_CREATE,
    SOCKTRACE_SYSCALL_EPOLL_CREATE1,
    SOCKTRACE_SYSCALL_EPOLL_CTL,
    SOCKTRACE_SYSCALL_EPOLL_WAIT,
    SOCKTRACE_SYSCALL_EPOLL_PWAIT,
    SOCKTRACE_SYSCALL_EPOLL_PWAIT2,
    SOCKTRACE_SYSCALL_SENDFILE64,
    SOCKTRACE_SYSCALL_IOCTL,
    SOCKTRACE_SYSCALL_FCNTL,
    SOCKTRACE_SYSCALL_SPLICE,
    SOCKTRACE_SYSCALL_TEE,
    SOCKTRACE_SYSCALL_DUP,
    SOCKTRACE_SYSCALL_DUP2,
    SOCKTRACE_SYSCALL_DUP3,
    SOCKTRACE_SYSCALL_MAX
};

typedef enum socktrace_syscall socktrace_syscall_t;

const char* syscall_strings[] = {
    [SOCKTRACE_SYSCALL_SOCKET] = "socket",
    [SOCKTRACE_SYSCALL_BIND] = "bind",
    [SOCKTRACE_SYSCALL_LISTEN] = "listen",
    [SOCKTRACE_SYSCALL_CONNECT] = "connect",
    [SOCKTRACE_SYSCALL_ACCEPT] = "accept",
    [SOCKTRACE_SYSCALL_ACCEPT4] = "accept4",
    [SOCKTRACE_SYSCALL_RECVFROM] = "recvfrom",
    [SOCKTRACE_SYSCALL_RECVMSG] = "recvmsg",
    [SOCKTRACE_SYSCALL_RECVMMSG] = "recvmmsg",
    [SOCKTRACE_SYSCALL_SENDTO] = "sendto",
    [SOCKTRACE_SYSCALL_SENDMSG] = "sendmsg",
    [SOCKTRACE_SYSCALL_SENDMMSG] = "sendmmsg",
    [SOCKTRACE_SYSCALL_SETSOCKOPT] = "setsockopt",
    [SOCKTRACE_SYSCALL_GETSOCKOPT] = "getsockopt",
    [SOCKTRACE_SYSCALL_GETPEERNAME] = "getpeername",
    [SOCKTRACE_SYSCALL_GETSOCKNAME] = "getsockname",
    [SOCKTRACE_SYSCALL_SHUTDOWN] = "shutdown",
    [SOCKTRACE_SYSCALL_READ] = "read",
    [SOCKTRACE_SYSCALL_READV] = "readv",
    [SOCKTRACE_SYSCALL_WRITE] = "write",
    [SOCKTRACE_SYSCALL_WRITEV] = "writev",
    [SOCKTRACE_SYSCALL_CLOSE] = "close",
    [SOCKTRACE_SYSCALL_POLL] = "poll",
    [SOCKTRACE_SYSCALL_PPOLL] = "ppoll",
    [SOCKTRACE_SYSCALL_SELECT] = "select",
    [SOCKTRACE_SYSCALL_PSELECT] = "pselect",
    [SOCKTRACE_SYSCALL_EPOLL_CREATE] = "epoll_create",
    [SOCKTRACE_SYSCALL_EPOLL_CREATE1] = "epoll_create1",
    [SOCKTRACE_SYSCALL_EPOLL_CTL] = "epoll_ctl",
    [SOCKTRACE_SYSCALL_EPOLL_WAIT] = "epoll_wait",
    [SOCKTRACE_SYSCALL_EPOLL_PWAIT] = "epoll_pwait",
    [SOCKTRACE_SYSCALL_EPOLL_PWAIT2] = "epoll_pwait2",
    [SOCKTRACE_SYSCALL_SENDFILE64] = "sendfile",
    [SOCKTRACE_SYSCALL_IOCTL] = "ioctl",
    [SOCKTRACE_SYSCALL_SPLICE] = "splice",
    [SOCKTRACE_SYSCALL_TEE] = "tee",
    [SOCKTRACE_SYSCALL_DUP] = "dup",
    [SOCKTRACE_SYSCALL_DUP2] = "dup2",
    [SOCKTRACE_SYSCALL_DUP3] = "dup3",
};

typedef struct {
    struct pollfd* fds;
    int nbfds;
    socktrace_syscall_t syscall;
} poll_context_t;

typedef struct {
    __u32 nbfds;
    fd_set* reads;
    fd_set* writes;
    fd_set* excepts;
    socktrace_syscall_t syscall;
} select_context_t;

typedef struct {
    struct epoll_event* events;
    socktrace_syscall_t syscall;
} epoll_waitx_context_t;

#define SOCKTRACE_CLOSED_RD (1 << 0)
#define SOCKTRACE_CLOSED_WR (1 << 1)
#define SOCKTRACE_CLOSED_RDWR (SOCKTRACE_CLOSED_RD | SOCKTRACE_CLOSED_WR)

typedef struct {
    __u64 inode;
    int how_closed;
} sock_ctx_t;

typedef struct {
    __u64 sock_cookie; /* global socket identifier */
    __u64 parent_cookie; /* accept()/epoll(): cookie of the listening socket, else 0 */
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    socktrace_syscall_t op;
    __u32 fd;
} sock_event_t;

#define caller_check()                              \
    do {                                            \
        __u64 pidtgid = bpf_get_current_pid_tgid(); \
        __u32 tgid = pidtgid >> 32;                 \
        if (tgid != target_pid)                     \
            return 0;                               \
    } while (0)

#endif
