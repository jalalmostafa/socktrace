#ifndef SOCKSTATS_BPF_H
#define SOCKSTATS_BPF_H

#define SOCKSTATS_NFDBITS (8 * sizeof(unsigned long))
#define SOCKSTATS_NFDBITS_MASK (SOCKSTATS_NFDBITS - 1)
#define SOCKSTATS_LENGTH (1024 / SOCKSTATS_NFDBITS)

#define MAX_PROCESSES 256
#define MAX_SOCKETS SOCKSTATS_NFDBITS

#define FIRST_ARG(ctx) (ctx->args[0])
#define FD(ctx) (FIRST_ARG(ctx))

#define REGSOCK 1

#endif
