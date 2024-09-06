#include "vmlinux.h"

#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "sockstats.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
    struct pollfd* fds;
    int nbfds;
    sockstats_syscall_t syscall;
} poll_context_t;

typedef struct {
    __u32 nbfds;
    fd_set* reads;
    fd_set* writes;
    fd_set* excepts;
    sockstats_syscall_t syscall;
} select_context_t;

__u32 target_pid = 0;

#define caller_check()                              \
    do {                                            \
        __u64 pidtgid = bpf_get_current_pid_tgid(); \
        __u32 tgid = pidtgid >> 32;                 \
        if (tgid != target_pid)                     \
            return 0;                               \
    } while (0)

static inline unsigned int FD_ISSET(int fd, fd_set* set)
{
    if (fd < 0 || set == NULL)
        return 0;

    int idx = (int)(fd / SOCKSTATS_NFDBITS);

    if (idx >= 0 && idx < 16) {
        unsigned long slot;
        // FIXME: maybe we can generalize this again
        if (bpf_probe_read_user(&slot, sizeof(slot), set->fds_bits + idx) < 0) {
            bpf_printk("bpf_probe_read_user error reading 'fd_set' from user space.\n");
            return 0;
        }

        return !!(slot & (1U << (fd & SOCKSTATS_NFDBITS_MASK)));
    }

    return 0;
}

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_PROCESSES);
//     __type(key, pid_t); // PID
//     __uint(value_size, sizeof(struct syscalls)); // counters
// } processes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u32); // Sock FD
    __type(value, __u32); // Socket data map
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u32); // Sock FD
    __type(value, __u32); // 0, updated to 1 when sock fd is updated
} reg_sockets SEC(".maps");

static int is_socket(int fd)
{
    __u32* value = bpf_map_lookup_elem(&reg_sockets, &fd);
    if (value == NULL || *value != REGSOCK)
        return 0;

    return 1;
}

static int tp_process_fd(sockstats_syscall_t syscall, __u32 fd)
{
    if (!is_socket(fd))
        return 0;

    void* map = bpf_map_lookup_elem(&sockets, &fd);
    if (map == NULL) {
        bpf_printk("Inner map is null on FD=%d\n", fd);
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct syscalls* calls = bpf_map_lookup_elem(map, &pid);
    if (calls == NULL) {
        struct syscalls zeros = { 0 };
        if (bpf_map_update_elem(map, &pid, &zeros, 0) < 0) {
            bpf_printk("Failed initializing syscalls counters\n");
            return 0;
        }
    }
    calls = bpf_map_lookup_elem(map, &pid);

    if (calls != NULL && syscall >= 0 && syscall < SOCKSTATS_SYSCALL_MAX) {
        __u32* counter = &calls->counters[syscall];
        __sync_fetch_and_add(counter, 1);
    }

    return 0;
}

static long tp_poll_cb(__u32 index, poll_context_t* ctx)
{
    struct pollfd pfd;
    if (bpf_probe_read_user(&pfd, sizeof(struct pollfd), ctx->fds + index) < 0) {
        bpf_printk("bpf_probe_read_user error reading 'pollfds' from user space\n");
        return 0;
    }

    return tp_process_fd(ctx->syscall, pfd.fd);
}

static int tp_poll_process(sockstats_syscall_t syscall, struct pollfd* fds, __u32 nbfds)
{
    poll_context_t ctx = { .fds = fds, .nbfds = nbfds, .syscall = syscall };
    int ret = bpf_loop(nbfds, tp_poll_cb, &ctx, 0);
    if (ret < 0) {
        bpf_printk("tp_poll_process: bpf_loop failed and returned %d\n", ret);
        return 0;
    }

    return 0;
}

static long tp_select_cb(__u32 idx, select_context_t* ctx)
{
    if (FD_ISSET(idx, ctx->reads))
        tp_process_fd(ctx->syscall, idx);

    if (FD_ISSET(idx, ctx->writes))
        tp_process_fd(ctx->syscall, idx);

    if (FD_ISSET(idx, ctx->excepts))
        tp_process_fd(ctx->syscall, idx);

    return 0;
}

static int tp_select_process(sockstats_syscall_t syscall, __u32 nbfds, fd_set* reads, fd_set* writes, fd_set* excepts)
{
    select_context_t ctx = { .nbfds = nbfds, .reads = reads, .writes = writes, .excepts = excepts, .syscall = syscall };
    int ret = bpf_loop(nbfds, tp_select_cb, &ctx, 0);
    if (ret < 0) {
        bpf_printk("tp_select_process: bpf_loop failed and returned %d\n", ret);
        return 0;
    }

    return 0;
}

static inline int tp_new_fd(sockstats_syscall_t syscall, int fd)
{
    int reg = REGSOCK;

    if (fd < 0 || bpf_map_update_elem(&reg_sockets, &fd, &reg, BPF_ANY) < 0) {
        bpf_printk("Invalid FD=%d or cannot be registered\n", fd);
        return 0;
    }

    return tp_process_fd(syscall, fd);
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int fd = ctx->ret;
    return tp_new_fd(SOCKSTATS_SYSCALL_SOCKET, fd);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_BIND, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_LISTEN, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_ACCEPT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_ACCEPT4, FD(ctx));
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int fd = ctx->ret;

    return tp_new_fd(SOCKSTATS_SYSCALL_ACCEPT, fd);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept4(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int fd = ctx->ret;

    return tp_new_fd(SOCKSTATS_SYSCALL_ACCEPT4, fd);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_RECVFROM, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint__syscalls__sys_enter_recvmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_RECVMSG, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint__syscalls__sys_enter_recvmmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_RECVMMSG, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_SENDTO, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_SENDMSG, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint__syscalls__sys_enter_sendmmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_SENDMMSG, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int tracepoint__syscalls__sys_enter_getsockopt(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_GETSOCKOPT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tracepoint__syscalls__sys_enter_setsockopt(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_SETSOCKOPT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int tracepoint__syscalls__sys_enter_getpeername(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_GETPEERNAME, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int tracepoint__syscalls__sys_enter_getsockname(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_GETSOCKNAME, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_CONNECT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int tracepoint__syscalls__sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_SHUTDOWN, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_READ, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_READV, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_WRITE, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_WRITEV, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_CLOSE, FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_poll")
int tracepoint__syscalls__sys_enter_poll(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    struct pollfd* fds = (struct pollfd*)((void*)ctx->args[0]);
    __u32 nfds = ctx->args[1];
    return tp_poll_process(SOCKSTATS_SYSCALL_POLL, fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int tracepoint__syscalls__sys_enter_ppoll(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    struct pollfd* fds = (struct pollfd*)((void*)ctx->args[0]);
    __u32 nfds = ctx->args[1];
    return tp_poll_process(SOCKSTATS_SYSCALL_PPOLL, fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_select")
int tracepoint__syscalls__sys_enter_select(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    __u32 nbfds = ctx->args[0];
    fd_set* reads = (fd_set*)((void*)ctx->args[1]);
    fd_set* writes = (fd_set*)((void*)ctx->args[2]);
    fd_set* excepts = (fd_set*)((void*)ctx->args[3]);

    return tp_select_process(SOCKSTATS_SYSCALL_SELECT, nbfds, reads, writes, excepts);
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int tracepoint__syscalls__sys_enter_pselect6(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    __u32 nbfds = ctx->args[0];
    fd_set* reads = (fd_set*)((void*)ctx->args[1]);
    fd_set* writes = (fd_set*)((void*)ctx->args[2]);
    fd_set* excepts = (fd_set*)((void*)ctx->args[3]);

    return tp_select_process(SOCKSTATS_SYSCALL_PSELECT, nbfds, reads, writes, excepts);
}

SEC("tracepoint/syscalls/sys_exit_epoll_create")
int tracepoint__syscalls__sys_enter_epoll_create(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int fd = ctx->ret;
    return tp_new_fd(SOCKSTATS_SYSCALL_EPOLL_CREATE, fd);
}

SEC("tracepoint/syscalls/sys_exit_epoll_create1")
int tracepoint__syscalls__sys_enter_epoll_create1(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int fd = ctx->ret;
    return tp_new_fd(SOCKSTATS_SYSCALL_EPOLL_CREATE1, fd);
}

SEC("tracepoint/syscalls/sys_exit_epoll_ctl")
int tracepoint__syscalls__sys_enter_epoll_ctl(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    int epfd = FD(ctx);
    int sockfd = ctx->args[2];
    return tp_process_fd(SOCKSTATS_SYSCALL_EPOLL_CTL, epfd) && tp_process_fd(SOCKSTATS_SYSCALL_EPOLL_CTL, sockfd);
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int tracepoint__syscalls__sys_enter_epoll_wait(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_EPOLL_WAIT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int tracepoint__syscalls__sys_enter_epoll_pwait(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_EPOLL_PWAIT, FD(ctx));
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait2")
int tracepoint__syscalls__sys_enter_epoll_pwait2(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();

    return tp_process_fd(SOCKSTATS_SYSCALL_EPOLL_PWAIT2, FD(ctx));
}