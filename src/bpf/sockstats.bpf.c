#include "vmlinux.h"

#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "sockstats.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
    struct pollfd* fds;
    int nbfds;
} poll_context_t;

typedef struct {
    __u32 nbfds;
    fd_set* reads;
    fd_set* writes;
    fd_set* excepts;
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
        if (bpf_probe_read_user(&slot, sizeof(slot), set->fds_bits + idx) < 0) {
            bpf_printk("bpf_probe_read_user error reading 'fd_set' from user space.\n");
            return 0;
        }

        return !!(slot & (1U << (fd & SOCKSTATS_NFDBITS_MASK)));
    }

    return 0;
}

// TODO: also collect stats per syscall

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32); // PID
    __type(value, __u32); // Counter
} processes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
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

static int tp_process_fd(__u32 fd)
{
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    __u32 pid = pidtgid & 0xFFFFFFFF;

    if (tgid != target_pid || !is_socket(fd))
        return 0;

    void* map = bpf_map_lookup_elem(&sockets, &fd);
    if (map == NULL) {
        bpf_printk("Inner map is null on FD=%d\n", fd);
        return 0;
    }

    __u32 ncounter = 1;
    __u32* counter = bpf_map_lookup_elem(map, &pid);
    if (counter == NULL) {
        if (bpf_map_update_elem(map, &pid, &ncounter, 0) < 0)
            bpf_printk("Failed setting counter on FD=%d \n", fd);
    } else
        __sync_fetch_and_add(counter, 1);

    return 0;
}

static long tp_poll_cb(__u32 index, poll_context_t* ctx)
{
    struct pollfd pfd;
    if (bpf_probe_read_user(&pfd, sizeof(struct pollfd), ctx->fds + index) < 0) {
        bpf_printk("bpf_probe_read_user error reading 'pollfds' from user space\n");
        return 0;
    }

    return tp_process_fd(pfd.fd);
}

static int tp_poll_process(struct pollfd* fds, __u32 nbfds)
{
    poll_context_t ctx = { .fds = fds, .nbfds = nbfds };
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
        tp_process_fd(idx);

    if (FD_ISSET(idx, ctx->writes))
        tp_process_fd(idx);

    if (FD_ISSET(idx, ctx->excepts))
        tp_process_fd(idx);

    return 0;
}

static int tp_select_process(__u32 nbfds, fd_set* reads, fd_set* writes, fd_set* excepts)
{
    select_context_t ctx = { .nbfds = nbfds, .reads = reads, .writes = writes, .excepts = excepts };
    int ret = bpf_loop(nbfds, tp_select_cb, &ctx, 0);
    if (ret < 0) {
        bpf_printk("tp_select_process: bpf_loop failed and returned %d\n", ret);
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int reg = REGSOCK;
    int fd = ctx->ret;

    if (fd < 0 || bpf_map_update_elem(&reg_sockets, &fd, &reg, BPF_ANY) < 0) {
        bpf_printk("Invalid FD=%d or cannot be registered\n", fd);
        return 0;
    }

    return tp_process_fd(fd);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int reg = REGSOCK;
    int fd = ctx->ret;

    if (fd < 0 || bpf_map_update_elem(&reg_sockets, &fd, &reg, BPF_ANY) < 0) {
        bpf_printk("Invalid FD=%d or cannot be registered\n", fd);
        return 0;
    }

    return tp_process_fd(fd);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept4(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();

    int reg = REGSOCK;
    int fd = ctx->ret;
    if (fd < 0 || bpf_map_update_elem(&reg_sockets, &fd, &reg, BPF_ANY) < 0) {
        bpf_printk("Invalid FD=%d or cannot be registered\n", fd);
        return 0;
    }

    return tp_process_fd(fd);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint__syscalls__sys_enter_recvmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint__syscalls__sys_enter_recvmmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint__syscalls__sys_enter_sendmmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int tracepoint__syscalls__sys_enter_getsockopt(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tracepoint__syscalls__sys_enter_setsockopt(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int tracepoint__syscalls__sys_enter_getpeername(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int tracepoint__syscalls__sys_enter_getsockname(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int tracepoint__syscalls__sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_fd(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_poll")
int tracepoint__syscalls__sys_enter_poll(struct trace_event_raw_sys_enter* ctx)
{
    struct pollfd* fds = (struct pollfd*)((void*)ctx->args[0]);
    __u32 nfds = ctx->args[1];
    return tp_poll_process(fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int tracepoint__syscalls__sys_enter_ppoll(struct trace_event_raw_sys_enter* ctx)
{
    struct pollfd* fds = (struct pollfd*)((void*)ctx->args[0]);
    __u32 nfds = ctx->args[1];
    return tp_poll_process(fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_select")
int tracepoint__syscalls__sys_enter_select(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    __u32 nbfds = ctx->args[0];
    fd_set* reads = (fd_set*)((void*)ctx->args[1]);
    fd_set* writes = (fd_set*)((void*)ctx->args[2]);
    fd_set* excepts = (fd_set*)((void*)ctx->args[3]);

    return tp_select_process(nbfds, reads, writes, excepts);
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int tracepoint__syscalls__sys_enter_pselect6(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    __u32 nbfds = ctx->args[0];
    fd_set* reads = (fd_set*)((void*)ctx->args[1]);
    fd_set* writes = (fd_set*)((void*)ctx->args[2]);
    fd_set* excepts = (fd_set*)((void*)ctx->args[3]);

    return tp_select_process(nbfds, reads, writes, excepts);
}
