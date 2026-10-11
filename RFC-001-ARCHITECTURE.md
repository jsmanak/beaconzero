# RFC-001: BeaconZero Architecture

## 1. Problem Statement
Genomic sequences are immutable biometric identifiers. Standard database engines grant broad filesystem read descriptors across multi-gigabyte VCF/BAM archives to check single variants. BeaconZero eliminates over-privileged I/O by confining reads at the OS kernel layer.

## 2. Invariants
- No worker process may read unindexed genomic coordinates.
- Unauthorized seeks or full-file scans return `-EPERM` at the VFS layer.
- Raw SAM/FASTQ sequence headers (`@HD`, `@SQ`) are discarded by the kernel network stack before egress.
