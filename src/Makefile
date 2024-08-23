
CFLAGS += -g -O2 -std=gnu11 -I$(LIBBPF_PATH)

BPF_CFLAGS += -Ibpf -I$(LIBBPF_PATH)

BPF_TARGET := bpf

ifeq ($(VERBOSE), 0)
	QUIET_CC       = @echo '  CC       '$@;
	QUIET_CLANG    = @echo '  CLANG    '$@;
	QUIET_LLC      = @echo '  LLC      '$@;
	QUIET_LINK     = @echo '  LINK     '$@;
	QUIET_INSTALL  = @echo '  INSTALL  '$@;
	QUIET_M4       = @echo '  M4       '$@;
	QUIET_GEN      = @echo '  GEN      '$@;
	QUIET_STRIP    = @echo '  STRIP    '$@;
	QUIET_BPFTOOL  = echo '  BPFTOOL  '$@;
endif

all: sockstats

LDFLAGS += -L$(LIBBPF_PATH) -l:libbpf.a -lelf -lz

sockstats: %: %.c $(LIBBPF_ARCHIVE) vmlinux sockstats.skel.h
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $< $(LDFLAGS) -o $@ 

sockstats.skel.h: bpf/sockstats.bpf.o
	$(Q)$(QUIET_BPFTOOL)bpftool gen skeleton ${<:.c=.o} > $@

bpf/sockstats.bpf.o: bpf/%.o: bpf/%.c
	$(QUIET_CLANG)clang -S -target $(BPF_TARGET) \
		-D __BPF_TRACING__ $(BPF_CFLAGS) -Wall -Wno-unused-value \
		-Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)llc -march=$(BPF_TARGET) -filetype=obj -o $@ ${@:.o=.ll}
	$(QUIET_STRIP)llvm-strip -g $@

clean:
	$(Q)rm -rf *.o sockstats bpf/*.o bpf/*.ll bpf/vmlinux.h

vmlinux:
	$(Q)if [ ! -f bpf/vmlinux.h ]; then $(QUIET_BPFTOOL)bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h ; fi
