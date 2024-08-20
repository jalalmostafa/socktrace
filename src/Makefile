
CFLAGS += -g -O2

BPF_HEADERS := $(wildcard bpf/*.h)
BPF_CFLAGS += -I$(BPF_HEADERS)

BPF_TARGET := bpf

ifeq ($(VERBOSE), 0)
    QUIET_CC       = @echo '  CC       '$@;
    QUIET_CLANG    = @echo '  CLANG    '$@;
    QUIET_LLC      = @echo '  LLC      '$@;
    QUIET_LINK     = @echo '  LINK     '$@;
    QUIET_INSTALL  = @echo '  INSTALL  '$@;
    QUIET_M4       = @echo '  M4       '$@;
    QUIET_GEN      = @echo '  GEN      '$@;
endif

all: vmlinux sockstats bpf/sockstats.bpf.o

LDFLAGS += 
LDLIBS += -L$(LIBBPF_PATH) -l:libbpf.a

sockstats: %: %.c $(LIBBPF_ARCHIVE)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(LDLIBS) $<

bpf/sockstats.bpf.o: bpf/%.o: bpf/%.c
	$(QUIET_CLANG)clang -S -target $(BPF_TARGET) \
	    -D __BPF_TRACING__ $(BPF_CFLAGS) -Wall -Wno-unused-value \
	    -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)llc -march=$(BPF_TARGET) -filetype=obj -o $@ ${@:.o=.ll}

clean:
	$(Q)rm -rf *.o sockstats bpf/*.o bpf/*.ll bpf/vmlinux.h

vmlinux:
	$(Q)if [ ! -f bpf/vmlinux.h ]; then bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; fi