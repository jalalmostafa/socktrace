all:
	@go generate
	@go build

.PHONY: clean
clean:
	@echo "Cleaning socktrace..."
	@rm -rf *.o sockstats.skel.h sockstats bpf/*.o bpf/*.ll socktraceebpf_bpfe*.go socktrace
