#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <libbpf.h>
#include <bpf.h>

#include "sockstats.skel.h"
#include "bpf/sockstats.bpf.h"

void help(char* program)
{
    printf("Usage:\n"
           "%s <command>\n\n"
           "An eBPF tool to monitor how many threads did a socket use\n\n",
        program);
}

void launch_error(char** args, int argc)
{
    fprintf(stderr, "Error launching: ");
    for (int i = 0; i < argc; i++)
        fprintf(stderr, " %s", args[i]);
    fprintf(stderr, "\n");
}

void handler(int)
{
}

int fetch_maps(struct sockstats_bpf* bpf)
{
    int ret = 0;
    fprintf(stderr, "\nSocketFD\t\t|\t\tPID\t\t|\t\tTracked Syscalls\n");
    for (int i = 0; i < MAX_SOCKETS; i++) {
        __u32 mapid;
        if (bpf_map__lookup_elem(bpf->maps.sockets, &i, sizeof(__u32), &mapid, sizeof(__u32), 0) < 0) {
            perror("bpf_map__lookup_elem");
            break;
        }

        int mapfd = bpf_map_get_fd_by_id(mapid);
        if (mapfd < 0) {
            perror("bpf_map_get_fd_by_id");
            break;
        }

        __u32 *current = NULL, next, value;
        do {
            ret = bpf_map_get_next_key(mapfd, current, &next);
            if (ret < 0) {
                if (ret != -ENOENT)
                    perror("bpf_map_get_next_key");
                break;
            }

            current = &next;
            if (next != 0) {
                bpf_map_lookup_elem(mapfd, current, &value);
                fprintf(stderr, "%u\t\t\t|\t\t%u\t\t|\t\t%u\n", i, *current, value);
            }
        } while (ret != 0);
        close(mapfd);
    }

    return 0;
}

int main(int argc, char** argv)
{
    int pid = -1;
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

    char pipe_data;
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        ret = -1;
        goto exit;
    }

    pid = fork();
    if (pid > 0) {
        fprintf(stderr, "Launched process %d\n", pid);
        close(pipefd[0]);
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
            fprintf(stderr, "Error opening eBPF program\n");
            ret = -1;
            goto exit;
        }

        bpf->bss->target_pid = pid;
        int processes_mapfd = bpf_map_create(BPF_MAP_TYPE_HASH, "processes",
            sizeof(__u32), sizeof(__u32), MAX_PROCESSES, NULL);
        bpf_map__set_inner_map_fd(bpf->maps.sockets, processes_mapfd);

        ret = sockstats_bpf__load(bpf);
        close(processes_mapfd);
        if (ret < 0) {
            fprintf(stderr, "Error loading eBPF program\n");
            goto exit;
        }

        ret = sockstats_bpf__attach(bpf);
        if (ret < 0) {
            fprintf(stderr, "Error attaching eBPF program\n");
            goto exit;
        }
        is_ebpf_attached = true;

#define CHLD_MAP_NAME_MAXLEN 20
        char child_map_name[CHLD_MAP_NAME_MAXLEN];
        for (int i = 0; i < MAX_SOCKETS; i++) {
            snprintf(child_map_name, CHLD_MAP_NAME_MAXLEN, "processes_%u", i);
            int mapfd = bpf_map_create(BPF_MAP_TYPE_HASH, child_map_name, sizeof(__u32), sizeof(__u32), MAX_PROCESSES, NULL);
            if (bpf_map__update_elem(bpf->maps.sockets, &i, sizeof(__u32), &mapfd, sizeof(__u32), 0) < 0) {
                perror("bpf_map__update_elem");
                ret = -1;
                goto exit;
            }
        }

        (void)!write(pipefd[1], &pipe_data, sizeof(pipe_data));
        while (1) {
            alarm(1);

            // Wait for the child process to finish
            if (waitpid(pid, &wstatus, 0) == -1) {
                if (errno == EINTR)
                    if (fetch_maps(bpf) < 0)
                        break;

            } else if (WIFEXITED(wstatus))
                break;
        }
        alarm(0);
    } else if (pid == 0) {
        close(pipefd[1]);
        (void)!read(pipefd[0], &pipe_data, sizeof(pipe_data));
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

        kill(pid, SIGTERM);
    }

    return ret;
}
