# sockstats
A tool to discover BSD sockets concurrency statistics using eBPF

## Build

```bash
# install dependencies
apt install clang llvm libelf-dev build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r)
git clone --recursive git@github.com:jalalmostafa/sockstats.git
cd sockstats
make
```
