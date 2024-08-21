#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "sockstats.skel.h"

void help(char* program)
{
    printf("Usage:\n"
           "%s <command>\n\n"
           "An eBPF tool to monitor how many threads did a socket use\n\n",
        program);
}

void launch_error(char** args, int argc)
{
    printf("Error launching: ");
    for (int i = 0; i < argc; i++)
        printf(" %s", args[i]);
    printf("\n");
}

void handler(int)
{
}

int main(int argc, char** argv)
{
    int ret = 0, wstatus;
    bool is_ebpf_attached = false;
    struct sockstats_bpf* bpf = NULL;

    if (argc < 2) {
        help(argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2 && !strncmp("-h", argv[1], 3)) {
        help(argv[0]);
        ret = -1;
        goto exit;
    }

    char* program = argv[1];
    argv++;
    argc--;

    int pid = fork();
    if (pid > 0) {
        struct sigaction sa;
        sa.sa_handler = handler;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            perror("Error setting timer");
            ret = -1;
            goto exit;
        }

        bpf = sockstats_bpf__open();
        if (!bpf) {
            printf("Error opening eBPF program\n");
            ret = -1;
            goto exit;
        }

        bpf->bss->target_pid = pid;
        ret = sockstats_bpf__load(bpf);
        if (ret < 0) {
            printf("Error loading eBPF program\n");
            goto exit;
        }

        ret = sockstats_bpf__attach(bpf);
        if (ret < 0) {
            printf("Error attaching eBPF program\n");
            goto exit;
        }
        is_ebpf_attached = true;

        while (1) {
            alarm(1);

            // Wait for the child process to finish
            if (waitpid(pid, &wstatus, 0) == -1) {
                if (errno == EINTR)
                    printf("Received EINTR\n");
                // fetch maps

            } else if (WIFEXITED(wstatus))
                break;

            alarm(0);
        }
    } else if (pid == 0) {
        int ret = execvp(program, argv);
        if (ret < 0) {
            launch_error(argv, argc);
            ret = -1;
            goto exit;
        }
    } else {
        launch_error(argv, argc);
        ret = -1;
        goto exit;
    }

exit:
    if (pid > 0) {
        if (is_ebpf_attached)
            sockstats_bpf__detach(bpf);

        if (bpf)
            sockstats_bpf__destroy(bpf);
    }

    return ret;
}
