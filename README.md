# Socktrace

A tool to trace parallel system calls to BSD sockets using eBPF.
This tool answers the question: how many times has socket syscalls been called by each process in a program?

## To do

- [ ] Use TUI to print output

## Usage

```bash
Usage:
Usage: ./socktrace [options] program args..
  -d duration
        Run duration.
  -h    Prints this help text.
  -s duration
        Set sampling period
```

## Build

```bash
# install dependencies
apt install clang llvm libelf-dev build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) linux-tools-$(uname -r)-generic libbpf-dev golang
git clone https://github.com/jalalmostafa/socktrace.git
cd socktrace
make
```
