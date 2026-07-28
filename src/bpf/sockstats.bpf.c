#include "sockstats.bpf.h"

#define S_IFMT 00170000
#define S_IFSOCK 0140000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u32 target_pid = 0;
/**
 * @brief Filled from user-space using /proc/kallsyms
 * $ sudo cat /proc/kallsyms | grep eventpoll_fops
 * ffffffff82e56920 d eventpoll_fops
 */
unsigned long eventpoll_fops_ptr = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, (1 << 20));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u64); // TGID & Sock FD
    __type(value, sock_ctx_t);
} reg_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u64); // Child TGID & Sock FD
    __type(value, __u64); // Parent TGID & Sock FD
} parented_sockets SEC(".maps");

static inline const char* syscallstr(socktrace_syscall_t syscall)
{
    if (syscall < SOCKTRACE_SYSCALL_MAX)
        return syscall_strings[syscall];
    return NULL;
}

SEC("fentry/fd_install")
int BPF_PROG(trace_fd_install, unsigned int fd, struct file* file)
{
    caller_check();
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    unsigned long fops = (unsigned long)(void*)BPF_CORE_READ(file, f_op);
    if ((mode & S_IFMT) != S_IFSOCK && fops != eventpoll_fops_ptr)
        return 0;

    __u64 tgid_fd = (bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000) | fd;
    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);

    sock_ctx_t sock_ctx = {
        .how_closed = 0,
        .inode = inode
    };

    if (bpf_map_update_elem(&reg_sockets, &tgid_fd, &sock_ctx, BPF_ANY) < 0)
        bpf_printk("SOCKSTATS: Failed to add file descriptor: tgid=%u, fd=%u, inode=%llu", (__u32)(tgid_fd >> 32), (__u32)(tgid_fd & 0xFFFFFFFF), inode);

    return 0;
}

static inline unsigned int FD_ISSET(int fd, fd_set* set)
{
    if (fd < 0 || set == NULL)
        return 0;

    int idx = (int)(fd / SOCKTRACE_NFDBITS);

    if (idx >= 0 && idx < 16) {
        unsigned long slot;
        if (bpf_probe_read_user(&slot, sizeof(slot), set->fds_bits + idx) < 0) {
            bpf_printk("bpf_probe_read_user: error reading 'fd_set' from user space.");
            return 0;
        }

        return !!(slot & (1U << (fd & SOCKTRACE_NFDBITS_MASK)));
    }

    return 0;
}

static int tp_process_fd(socktrace_syscall_t syscall, __u32 fd)
{
    if (fd == 0 || fd == 1 || fd == 2)
        return 0;

    __u64 tgidpid = bpf_get_current_pid_tgid();
    __u64 tgid = tgidpid >> 32;
    __u32 pid = tgidpid & 0xFFFFFFFF;
    __u64 tgid_fd = (tgid << 32) | fd;
    __u64* inode = (__u64*)bpf_map_lookup_elem(&reg_sockets, &tgid_fd);

    if (inode == NULL)
        return 0;

    sock_event_t* ev = bpf_ringbuf_reserve(&events, sizeof(sock_event_t), 0);
    if (!ev)
        return 0;

    ev->fd = fd;
    ev->op = syscall;
    ev->tgid = tgid & 0xFFFFFFFF;
    ev->pid = pid;
    ev->ts_ns = bpf_ktime_get_ns();
    ev->sock_cookie = tgid_fd;
    ev->parent_cookie = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static long tp_epoll_cb(__u32 index, epoll_waitx_context_t* ctx)
{
    struct epoll_event ev;
    if (bpf_probe_read_user(&ev, sizeof(struct epoll_event), ctx->events + index) < 0) {
        bpf_printk("bpf_probe_read_user: error reading 'events' from user space");
        return 0;
    }
    return tp_process_fd(ctx->syscall, (__u32)ev.data);
}

static int tp_process_epoll_waitx(socktrace_syscall_t syscall, struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    int count = (int)ctx->args[0];
    int epfd = (int)ctx->args[1];
    epoll_waitx_context_t ectx = {
        .events = (struct epoll_event*)ctx->args[2],
        .syscall = syscall
    };

    int ret = bpf_loop(count, tp_epoll_cb, &ectx, 0);
    if (ret < 0) {
        bpf_printk("tp_process_epoll_waitx: bpf_loop failed and returned %d", ret);
        return 0;
    }

    return tp_process_fd(syscall, epfd);
}

static long tp_poll_cb(__u32 index, poll_context_t* ctx)
{
    struct pollfd pfd;
    if (bpf_probe_read_user(&pfd, sizeof(struct pollfd), ctx->fds + index) < 0) {
        bpf_printk("bpf_probe_read_user: error reading 'pollfds' from user space");
        return 0;
    }
    return tp_process_fd(ctx->syscall, pfd.fd);
}

static int tp_poll_process(socktrace_syscall_t syscall, struct pollfd* fds, __u32 nbfds)
{
    poll_context_t ctx = { .fds = fds, .nbfds = nbfds, .syscall = syscall };
    int ret = bpf_loop(nbfds, tp_poll_cb, &ctx, 0);
    if (ret < 0) {
        bpf_printk("tp_poll_process: bpf_loop failed and returned %d", ret);
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

static int tp_select_process(socktrace_syscall_t syscall, __u32 nbfds, fd_set* reads, fd_set* writes, fd_set* excepts)
{
    select_context_t ctx = { .nbfds = nbfds, .reads = reads, .writes = writes, .excepts = excepts, .syscall = syscall };
    int ret = bpf_loop(nbfds, tp_select_cb, &ctx, 0);
    if (ret < 0) {
        bpf_printk("tp_select_process: bpf_loop failed and returned %d", ret);
        return 0;
    }

    return 0;
}

static void socket_delete(__u32 fd, int how_closed)
{
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u64 tgidfd = (pidtgid & 0xFFFFFFFF00000000) | fd;

    sock_ctx_t* sock = bpf_map_lookup_elem(&reg_sockets, &tgidfd);
    if (!sock)
        return;

    if (how_closed == SHUT_RDWR || how_closed == SHUT_RD)
        sock->how_closed |= SOCKTRACE_CLOSED_RD;
    if (how_closed == SHUT_RDWR || how_closed == SHUT_WR)
        sock->how_closed |= SOCKTRACE_CLOSED_WR;

    if (sock->how_closed == SOCKTRACE_CLOSED_RDWR) {
        if (bpf_map_delete_elem(&reg_sockets, &tgidfd) < 0)
            bpf_printk("Removing Socket TGID=%llu FD=%lu Failed", tgidfd >> 32, fd);
    }
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_SOCKET, (__u32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_BIND, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_LISTEN, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_ACCEPT, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_ACCEPT4, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_ACCEPT, (__u32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept4(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_ACCEPT4, (__u32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_RECVFROM, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint__syscalls__sys_enter_recvmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_RECVMSG, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint__syscalls__sys_enter_recvmmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_RECVMMSG, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_SENDTO, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_SENDMSG, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint__syscalls__sys_enter_sendmmsg(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_SENDMMSG, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int tracepoint__syscalls__sys_enter_getsockopt(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_GETSOCKOPT, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tracepoint__syscalls__sys_enter_setsockopt(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_SETSOCKOPT, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int tracepoint__syscalls__sys_enter_getpeername(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_GETPEERNAME, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int tracepoint__syscalls__sys_enter_getsockname(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_GETSOCKNAME, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_CONNECT, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int tracepoint__syscalls__sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    int fd = (__u32)ctx->args[0];
    int how = (__u32)ctx->args[1];
    int ret = tp_process_fd(SOCKTRACE_SYSCALL_SHUTDOWN, fd);
    socket_delete(fd, how);
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_READ, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_READV, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_WRITE, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_WRITEV, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    __u32 fd = (__u32)ctx->args[0];
    int ret = tp_process_fd(SOCKTRACE_SYSCALL_CLOSE, fd);
    socket_delete(fd, SHUT_RDWR);
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int tracepoint__syscalls__sys_enter_poll(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    struct pollfd* fds = (struct pollfd*)ctx->args[0];
    __u32 nfds = (__u32)ctx->args[1];
    return tp_poll_process(SOCKTRACE_SYSCALL_POLL, fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int tracepoint__syscalls__sys_enter_ppoll(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    struct pollfd* fds = (struct pollfd*)ctx->args[0];
    __u32 nfds = (__u32)ctx->args[1];
    return tp_poll_process(SOCKTRACE_SYSCALL_PPOLL, fds, nfds);
}

SEC("tracepoint/syscalls/sys_enter_select")
int tracepoint__syscalls__sys_enter_select(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    __u32 nbfds = (__u32)ctx->args[0];
    fd_set* reads = (fd_set*)ctx->args[1];
    fd_set* writes = (fd_set*)ctx->args[2];
    fd_set* excepts = (fd_set*)ctx->args[3];

    return tp_select_process(SOCKTRACE_SYSCALL_SELECT, nbfds, reads, writes, excepts);
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int tracepoint__syscalls__sys_enter_pselect6(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    __u32 nbfds = (__u32)ctx->args[0];
    fd_set* reads = (fd_set*)ctx->args[1];
    fd_set* writes = (fd_set*)ctx->args[2];
    fd_set* excepts = (fd_set*)ctx->args[3];
    return tp_select_process(SOCKTRACE_SYSCALL_PSELECT, nbfds, reads, writes, excepts);
}

SEC("tracepoint/syscalls/sys_exit_epoll_create")
int tracepoint__syscalls__sys_exit_epoll_create(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_EPOLL_CREATE, (__u32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_epoll_create1")
int tracepoint__syscalls__sys_exit_epoll_create1(struct trace_event_raw_sys_exit* ctx)
{
    caller_check();
    return tp_process_fd(SOCKTRACE_SYSCALL_EPOLL_CREATE1, (__u32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int tracepoint__syscalls__sys_enter_epoll_ctl(struct trace_event_raw_sys_enter* ctx)
{
    caller_check();
    int epfd = (__u32)ctx->args[0];
    int sockfd =(__u32)ctx->args[2];
    return tp_process_fd(SOCKTRACE_SYSCALL_EPOLL_CTL, epfd) && tp_process_fd(SOCKTRACE_SYSCALL_EPOLL_CTL, sockfd);
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int tracepoint__syscalls__sys_enter_epoll_wait(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_epoll_waitx(SOCKTRACE_SYSCALL_EPOLL_WAIT, ctx);
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int tracepoint__syscalls__sys_enter_epoll_pwait(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_epoll_waitx(SOCKTRACE_SYSCALL_EPOLL_PWAIT, ctx);
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int tracepoint__syscalls__sys_enter_epoll_pwait2(struct trace_event_raw_sys_enter* ctx)
{
    return tp_process_epoll_waitx(SOCKTRACE_SYSCALL_EPOLL_PWAIT2, ctx);
}
