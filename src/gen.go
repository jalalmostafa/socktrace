package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux SocktraceEbpf bpf/socktrace.bpf.c -- -g -O2 -Wall -Wno-missing-declarations
