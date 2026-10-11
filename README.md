# BeaconZero

[![CI](https://github.com/jsmanak/beaconzero/actions/workflows/ci.yml/badge.svg)](https://github.com/jsmanak/beaconzero/actions/workflows/ci.yml)

> **Kernel-Enforced, Zero-Trust Sovereign Genomic Query Gateway**

BeaconZero implements the [GA4GH Beacon v2](https://beacon-project.io/) discovery API backed by Linux kernel security primitives. It restricts genomic file access strictly to authorized 64 KB compressed blocks using eBPF LSM hooks and intercepts unmasked sequence data exfiltration at Layer 3 using cgroup socket filters.

## Core Architecture
- **Ingress & Policy (Proxy-Wasm):** Pure-Rust Tabix (`.tbi`) parsing and virtual offset planning.
- **Storage Isolation (eBPF LSM):** Intercepts `pread64` via `file_permission` hook to drop out-of-bounds reads with `-EPERM`.
- **Egress Guard (eBPF Cgroup SKB):** Layer 3 inspection to drop raw SAM/FASTQ sequence exfiltration streams.

See [RFC-001](RFC-001-ARCHITECTURE.md) for full architectural specifications.
