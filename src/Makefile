BPFTOOL := $(shell command -v bpftool 2>/dev/null)
ifeq ($(BPFTOOL),)
    $(error "bpftool not found. Please install it (e.g., sudo apt install linux-tools-common linux-tools-$(uname -r))")
endif

all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@go generate
	@go build

.PHONY: clean
clean:
	@echo "Cleaning socktrace..."
	@rm -rf *.o sockstats.skel.h sockstats bpf/*.o bpf/*.ll socktraceebpf_bpfe*.go socktrace
