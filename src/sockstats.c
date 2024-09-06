#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <libbpf.h>
#include <bpf.h>
#include <limits.h>

#include "sockstats.skel.h"
#include "bpf/sockstats.bpf.h"

#define CHLD_MAP_NAME_MAXLEN 20

void help(char* program)
{
    printf("Usage:\n"
           "%s <command>\n\n"
           "An eBPF tool to monitor how many threads did a socket use\n"
           "    -h        Print this help message\n"
           "    -t <nb>   Fetch statistics every <nb> seconds.\n"
           "              Default fetch at end of program or received signal to quit.\n"
           "\n\n",
        program);
}

void launch_error(char** args, int argc)
{
    fprintf(stderr, "Error launching: ");
    for (int i = 0; i < argc; i++)
        fprintf(stderr, " %s", args[i]);
    fprintf(stderr, "\n");
}

volatile bool quit = false;

void handler(int signo)
{
    if (signo == SIGTERM || signo == SIGINT) {
        quit = true;
        return;
    }
}

int fetch_maps(FILE* log, struct sockstats_bpf* bpf)
{
    int ret = 0;
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

        __u32 *current = NULL, next;
        struct syscalls value;
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
                fprintf(log, "%u, %u", i, *current);
                for (int j = 0; j < SOCKSTATS_SYSCALL_MAX; j++)
                    fprintf(log, ", %u", value.counters[j]);
                fprintf(log, "\n");
                fflush(log);
            }
        } while (ret != 0);
        close(mapfd);
    }

    return 0;
}

int fn(enum libbpf_print_level level, const char* str, va_list ap)
{
    if (level == LIBBPF_WARN)
        return vprintf(str, ap);
    return 0;
}

int main(int argc, char** argv)
{
    int pid = -1;
    int ret = 0, wstatus;
    bool is_ebpf_attached = false;
    struct sockstats_bpf* bpf = NULL;
    FILE* log = NULL;
    int opt_sample_duration = 0;

    if (argc < 2) {
        help(argv[0]);
        return EXIT_FAILURE;
    }

    char opt;
    int nbargs = 0;
    while ((opt = getopt(argc, argv, "ht:")) != -1) {
        switch (opt) {
        case 'h':
            help(argv[0]);
            return EXIT_SUCCESS;

        case 't':
            opt_sample_duration = atoi(optarg);
            break;

        default:
            fprintf(stderr, "Unknown argument '%c'\n", opt);
            help(argv[0]);
            return EXIT_FAILURE;
        }

        nbargs += 2 + (optarg == NULL ? 0 : strlen(optarg));
    }

    if (nbargs == 0)
        nbargs = 1;

    char* program = argv[nbargs];
    argv += nbargs;
    argc -= nbargs;

    char pipe_data;
    int pipefd[2];
    // pipe to synchronize parent and child
    if (pipe(pipefd) < 0) {
        ret = -1;
        goto exit;
    }

    pid = fork();
    if (pid > 0) {
        fprintf(stderr, "Launching process %d...\n", pid);
        char log_file[PATH_MAX];
        snprintf(log_file, PATH_MAX, "sockstats-%d.log", pid);
        log = fopen(log_file, "w");
        libbpf_set_print(fn);
        close(pipefd[0]);

        signal(SIGTERM, handler);
        signal(SIGINT, handler);

        struct sigaction sa;
        sa.sa_handler = handler;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        // Stop waitpid below using a SIGALRM timer
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
            sizeof(__u32), sizeof(struct syscalls), MAX_PROCESSES, NULL);
        if (processes_mapfd < 0) {
            perror("bpf_map_create");
            ret = -1;
            goto exit;
        }

        if (bpf_map__set_inner_map_fd(bpf->maps.sockets, processes_mapfd) < 0) {
            perror("bpf_map__set_inner_map_fd");
            ret = -1;
            close(processes_mapfd);
            goto exit;
        }

        ret = sockstats_bpf__load(bpf);
        close(processes_mapfd);
        if (ret < 0) {
            perror("Error loading eBPF program");
            goto exit;
        }

        ret = sockstats_bpf__attach(bpf);
        if (ret < 0) {
            fprintf(stderr, "Error attaching eBPF program\n");
            goto exit;
        }
        is_ebpf_attached = true;

        char processes_map_name[CHLD_MAP_NAME_MAXLEN];
        for (int i = 0; i < MAX_SOCKETS; i++) {
            snprintf(processes_map_name, CHLD_MAP_NAME_MAXLEN, "processes_%u", i);
            int proc_mapfd = bpf_map_create(BPF_MAP_TYPE_HASH,
                processes_map_name, sizeof(__u32), sizeof(struct syscalls), MAX_PROCESSES, NULL);

            if (bpf_map__update_elem(bpf->maps.sockets, &i, sizeof(__u32), &proc_mapfd, sizeof(__u32), 0) < 0) {
                perror("bpf_map__update_elem");
                ret = -1;
                goto exit;
            }
            close(proc_mapfd);
        }

        // Send signal to the child that we are ready
        // (void)! is used to ignore the -Wunused-result compiler warning
        (void)!write(pipefd[1], &pipe_data, sizeof(pipe_data));

        fprintf(log, "SocketFD, PID");
        for (int i = 0; i < SOCKSTATS_SYSCALL_MAX; i++)
            fprintf(log, ", %s", syscallstr((sockstats_syscall_t)i));
        fprintf(log, "\n");
        fflush(log);

        while (!quit) {
            if (opt_sample_duration > 0)
                alarm(opt_sample_duration);

            // Wait for the child process to finish
            if (waitpid(pid, &wstatus, 0) == -1) {
                // If SIGALRM interrupt was received
                if (errno == EINTR && opt_sample_duration > 0)
                    if (fetch_maps(log, bpf) < 0)
                        break;

            } else if (WIFEXITED(wstatus)) {
                if (opt_sample_duration <= 0)
                    fetch_maps(log, bpf);
                break;
            }
        }

        if (opt_sample_duration > 0)
            alarm(0);
        else
            fetch_maps(log, bpf);

    } else if (pid == 0) {
        close(pipefd[1]);
        // Wait the parent to be ready to intercept the child, wait for a signal
        // (void)! is used to ignore the -Wunused-result compiler warning
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
        if (log)
            fclose(log);

        if (is_ebpf_attached)
            sockstats_bpf__detach(bpf);

        if (bpf)
            sockstats_bpf__destroy(bpf);

        kill(pid, SIGTERM);
    }

    return ret;
}
