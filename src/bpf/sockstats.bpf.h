#ifndef SOCKSTATS_BPF_H
#define SOCKSTATS_BPF_H

#define MAX_PROCESSES 256
#define MAX_SOCKETS 256

#define FIRST_ARG(ctx) (ctx->args[0])
#define FD(ctx) (FIRST_ARG(ctx))

#endif
