#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    // u64 pid = bpf_get_current_pid_tgid() >> 32;
    /* use kernel terminology here for tgid/pid: */
    // if (pid != target_pid) {
        // return 0;
    // }
    /* store arg info for later lookup */
    // since we can manually specify the attach process in userspace,
    // we don't need to check the process allowed here

    // struct args_t args = {};
    // args.fname = (const char *)ctx->args[1];
    // args.flags = (int)ctx->args[2];
    // if (rewrite) {
    //     bpf_probe_write_user((char*)ctx->args[1], "hijacked", 9);
    // }
    // bpf_map_update_elem(&start, &pid, &args, 0);
    return 0;
}