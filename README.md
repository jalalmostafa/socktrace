# Socktrace

A tool to trace parallel system calls to BSD sockets using eBPF.
This tool answers the question: how many times has socket syscalls been called by each process in a program?

## To do

- [ ] Use TUI to print output
- [ ] relate to parent file descriptors (e.g. from accept and epoll)

## Usage

```bash
Usage: ./socktrace [options] program args..
  -f    Output Events to a CSV file.
  -h    Prints this help text.
```

## Build

```bash
# install dependencies
apt install clang llvm libelf-dev build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) linux-tools-$(uname -r) libbpf-dev golang
git clone https://github.com/jalalmostafa/socktrace.git
cd socktrace
make
```
