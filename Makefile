SHELL         := /bin/bash
.SHELLFLAGS   := -euo pipefail -c
CARGO         ?= cargo
SUDO          ?= sudo

.PHONY: all build build-wasm build-ebpf build-userspace test demo clean check-kernel

all: build

check-kernel:
	@grep -qs "bpf" /sys/kernel/security/lsm || (echo "BPF LSM not active in kernel" && exit 1)

build-wasm:
	$(CARGO) build --release --target wasm32-unknown-unknown -p beacon-tabix-wasm

build-ebpf:
	$(CARGO) xtask build-ebpf --release

build-userspace:
	$(CARGO) build --release --bins

build: build-wasm build-ebpf build-userspace

test: check-kernel
	@chmod +x ./run_test.sh && $(SUDO) ./run_test.sh

demo: check-kernel
	@chmod +x ./demo_beaconzero.sh && $(SUDO) ./demo_beaconzero.sh

clean:
	$(CARGO) clean
	@rm -rf /tmp/beaconzero_demo
