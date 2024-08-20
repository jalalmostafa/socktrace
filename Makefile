# SPDX-License-Identifier: GPL-2.0
# Top level Makefile
VERSION="0.0.1"

export VERBOSE = 0
ifeq ("$(origin V)", "command line")
  export VERBOSE = $(V)
endif

export Q = 
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

ifeq ($(VERBOSE),0)
  MAKEFLAGS += --no-print-directory
endif

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

TARGETS := libbpf src
.PHONY: check_submodule help clean $(TARGETS)

all: $(TARGETS)

src: check_submodule
	$(Q)$(MAKE) -C $@

export LIBBPF_PATH := $(abspath ./libbpf/src)
LIBBPF_SOURCES := $(wildcard $(LIBBPF_PATH)/*.[ch])
export LIBBPF_ARCHIVE := $(LIBBPF_PATH)/libbpf.a

$(LIBBPF_ARCHIVE): $(LIBBPF_SOURCES)

libbpf: $(LIBBPF_ARCHIVE)
	$(Q)$(MAKE) -C libbpf/src

.PHONY: libbpf_clean
libbpf_clean:
	$(Q)$(MAKE) -C libbpf/src clean

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"


check_submodule:
	@if [ -d .git ] && `git submodule status libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\

clean: libbpf_clean
	$(Q)$(MAKE) -C src clean
