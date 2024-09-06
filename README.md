# sockstats
A tool to discover BSD sockets concurrency statistics using eBPF

## To do

- [ ] Use TUI to print output
- [ ] Add option to output to file

## Usage

```bash
Usage:
./src/sockstats <command>

An eBPF tool to monitor how many threads did a socket use
    -h        Print this help message
    -t <nb>   Fetch statistics every <nb> seconds.
              Default fetch at end of program or received signal to quit.
```

## Build

```bash
# install dependencies
apt install clang llvm libelf-dev build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) linux-tools-$(uname -r)-generic
git clone --recursive https://github.com/jalalmostafa/sockstats.git
cd sockstats
make
```
