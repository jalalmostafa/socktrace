# sockstats
A tool to discover BSD sockets concurrency statistics using eBPF

## To do

- [ ] Use TUI to print output
- [ ] Add option to output to file
- [ ] Add support for poll/epoll hooks

## Usage

```bash
Usage:
./src/sockstats <command>

An eBPF tool to monitor how many threads did a socket use
```

## Build

```bash
# install dependencies
apt install clang llvm libelf-dev build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r)
git clone --recursive git@github.com:jalalmostafa/sockstats.git
cd sockstats
make
```
