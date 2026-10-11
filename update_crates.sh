#!/usr/bin/env bash
set -euo pipefail

echo "[*] Populating BeaconZero core crates..."

# 1. Update Root Cargo.toml
cat << 'CAT_EOF' > Cargo.toml
[workspace]
members = [
    "crates/beacon-tabix-wasm",
    "crates/beacon-lsm-common",
    "crates/beacon-lsm-ebpf",
    "crates/beacon-net-common",
    "crates/beacon-net-ebpf",
]
resolver = "2"

[package]
name = "beaconzero"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = "0.13"
aya-log = "0.2"
tokio = { version = "1.38", features = ["full"] }
anyhow = "1.0"
clap = { version = "4.5", features = ["derive"] }
beacon-lsm-common = { path = "crates/beacon-lsm-common", features = ["user"] }
beacon-net-common = { path = "crates/beacon-net-common", features = ["user"] }
CAT_EOF

# 2. Makefile
cat << 'CAT_EOF' > Makefile
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
CAT_EOF

# 3. crates/beacon-tabix-wasm
mkdir -p crates/beacon-tabix-wasm/src
cat << 'CAT_EOF' > crates/beacon-tabix-wasm/Cargo.toml
[package]
name = "beacon-tabix-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
noodles-tabix = "0.68"
noodles-bgzf = "0.52"
noodles-core = "0.21"
noodles-csi = "0.62"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-tabix-wasm/src/lib.rs
use std::io::{BufRead, Cursor, Read};
use noodles_bgzf as bgzf;
use noodles_core::{Position, Region};
use noodles_csi::binning_index::{index::reference_sequence::bin::Chunk, BinningIndex};
use noodles_tabix as tabix;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Failed to parse Tabix index: {0}")]
    IndexParseError(#[from] std::io::Error),
    #[error("Chromosome '{0}' not present in index")]
    ChromosomeNotFound(String),
    #[error("Invalid coordinate position: {0}")]
    InvalidPosition(usize),
    #[error("No genomic chunks overlap target locus")]
    NoOverlappingChunks,
    #[error("VCF parsing error: {0}")]
    VcfParseError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostFetchPlan {
    pub file_offset_start: u64,
    pub file_offset_end: u64,
    pub virtual_offset_start: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VariantMatch {
    pub chrom: String,
    pub pos: usize,
    pub reference: String,
    pub alternatives: Vec<String>,
    pub info: String,
}

pub struct TabixQueryEngine {
    index: tabix::Index,
}

impl TabixQueryEngine {
    pub fn from_index_bytes(index_bytes: &[u8]) -> Result<Self, QueryError> {
        let mut reader = tabix::io::Reader::new(Cursor::new(index_bytes));
        let index = reader.read_index()?;
        Ok(Self { index })
    }

    pub fn plan_fetch(&self, chrom: &str, pos: usize) -> Result<HostFetchPlan, QueryError> {
        let position = Position::try_from(pos).map_err(|_| QueryError::InvalidPosition(pos))?;
        let region = Region::new(chrom, position..=position);
        let header = self.index.header().ok_or_else(|| {
            QueryError::VcfParseError("Missing Tabix header".into())
        })?;

        let reference_sequence_id = self
            .index
            .reference_sequence_names(header)
            .get_index_of(chrom)
            .ok_or_else(|| QueryError::ChromosomeNotFound(chrom.to_string()))?;

        let chunks: Vec<Chunk> = self
            .index
            .query(reference_sequence_id, region.interval())
            .map_err(|e| QueryError::VcfParseError(e.to_string()))?;

        if chunks.is_empty() {
            return Err(QueryError::NoOverlappingChunks);
        }

        let first_chunk = &chunks[0];
        let v_start = first_chunk.start();
        let v_end = first_chunk.end();

        let file_offset_start = v_start.compressed();
        let file_offset_end = v_end.compressed().max(file_offset_start + 65536);

        Ok(HostFetchPlan {
            file_offset_start,
            file_offset_end,
            virtual_offset_start: u64::from(v_start),
        })
    }

    pub fn scan_block(
        &self,
        bgzf_chunk_bytes: &[u8],
        target_pos: usize,
    ) -> Result<Option<VariantMatch>, QueryError> {
        let mut decoder = bgzf::Reader::new(Cursor::new(bgzf_chunk_bytes));
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let cursor = Cursor::new(decompressed);
        let mut lines = cursor.lines();

        while let Some(Ok(line)) = lines.next() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 8 {
                continue;
            }
            if let Ok(line_pos) = fields[1].parse::<usize>() {
                if line_pos == target_pos {
                    return Ok(Some(VariantMatch {
                        chrom: fields[0].to_string(),
                        pos: line_pos,
                        reference: fields[3].to_string(),
                        alternatives: fields[4].split(',').map(|s| s.to_string()).collect(),
                        info: fields[7].to_string(),
                    }));
                } else if line_pos > target_pos {
                    break;
                }
            }
        }
        Ok(None)
    }
}
CAT_EOF

# 4. crates/beacon-lsm-common & crates/beacon-lsm-ebpf
mkdir -p crates/beacon-lsm-common/src crates/beacon-lsm-ebpf/src

cat << 'CAT_EOF' > crates/beacon-lsm-common/Cargo.toml
[package]
name = "beacon-lsm-common"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = { version = "0.13", default-features = false, optional = true }

[features]
user = ["dep:aya"]
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-lsm-common/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocusBoundary {
    pub target_inode: u64,
    pub start_offset: u64,
    pub end_offset: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LocusBoundary {}
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-lsm-ebpf/Cargo.toml
[package]
name = "beacon-lsm-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1.1"
beacon-lsm-common = { path = "../beacon-lsm-common" }

[[bin]]
name = "beacon-lsm-ebpf"
path = "src/main.rs"
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-lsm-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{file, pt_regs, task_struct},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, bpf_task_pt_regs},
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use beacon_lsm_common::LocusBoundary;

#[map]
static ACTIVE_BOUNDARIES: HashMap<u32, LocusBoundary> = HashMap::with_max_entries(1024, 0);

const EPERM: i32 = -1;
const MAY_READ: i32 = 0x00000004;
const X86_64_NR_PREAD64: u64 = 17;

#[lsm(hook = "file_permission")]
pub fn enforce_vcf_offset(ctx: LsmContext) -> i32 {
    unsafe { try_enforce_offset(ctx).unwrap_or(EPERM) }
}

unsafe fn try_enforce_offset(ctx: LsmContext) -> Result<i32, i32> {
    let file_ptr: *const file = ctx.arg(0);
    let mask: i32 = ctx.arg(1);

    if (mask & MAY_READ) == 0 || file_ptr.is_null() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let boundary = match ACTIVE_BOUNDARIES.get(&tgid) {
        Some(b) => b,
        None => return Ok(0),
    };

    let f_inode = bpf_probe_read_kernel(&(*file_ptr).f_inode).map_err(|_| EPERM)?;
    if f_inode.is_null() {
        return Ok(0);
    }
    let inode_num = bpf_probe_read_kernel(&(*f_inode).i_ino).map_err(|_| EPERM)?;

    if inode_num != boundary.target_inode {
        return Ok(0);
    }

    let task: *mut task_struct = bpf_get_current_task() as *mut task_struct;
    if task.is_null() {
        return Err(EPERM);
    }

    let regs_ptr: *mut pt_regs = bpf_task_pt_regs(task);
    if regs_ptr.is_null() {
        return Err(EPERM);
    }

    let syscall_nr = bpf_probe_read_kernel(&(*regs_ptr).orig_ax).map_err(|_| EPERM)?;
    let (req_offset, req_count) = if syscall_nr == X86_64_NR_PREAD64 {
        let offset = bpf_probe_read_kernel(&(*regs_ptr).r10).map_err(|_| EPERM)?;
        let count = bpf_probe_read_kernel(&(*regs_ptr).rdx).map_err(|_| EPERM)?;
        (offset, count)
    } else {
        let pos = bpf_probe_read_kernel(&(*file_ptr).f_pos).map_err(|_| EPERM)? as u64;
        let count = bpf_probe_read_kernel(&(*regs_ptr).rdx).map_err(|_| EPERM)?;
        (pos, count)
    };

    let req_end = req_offset.saturating_add(req_count);
    if req_offset < boundary.start_offset || req_end > boundary.end_offset {
        return Err(EPERM);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
CAT_EOF

# 5. crates/beacon-net-common & crates/beacon-net-ebpf
mkdir -p crates/beacon-net-common/src crates/beacon-net-ebpf/src

cat << 'CAT_EOF' > crates/beacon-net-common/Cargo.toml
[package]
name = "beacon-net-common"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = { version = "0.13", default-features = false, optional = true }

[features]
user = ["dep:aya"]
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-net-common/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterStats {
    pub packets_inspected: u64,
    pub packets_dropped: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterStats {}
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-net-ebpf/Cargo.toml
[package]
name = "beacon-net-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1.1"
beacon-net-common = { path = "../beacon-net-common" }

[[bin]]
name = "beacon-net-ebpf"
path = "src/main.rs"
CAT_EOF

cat << 'CAT_EOF' > crates/beacon-net-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::Array,
    programs::SkBuffContext,
};
use beacon_net_common::FilterStats;

#[map]
static STATS: Array<FilterStats> = Array::with_max_entries(1, 0);

const ACTION_ALLOW: i32 = 1;
const ACTION_DROP: i32 = 0;
const PROTO_TCP: u8 = 6;
const IPV4_MIN_HLEN: usize = 20;
const TCP_MIN_HLEN: usize = 20;
const INSPECTION_WINDOW: usize = 64;

#[cgroup_skb]
pub fn egress_leak_guard(ctx: SkBuffContext) -> i32 {
    let result = inspect_packet(&ctx);
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).packets_inspected = (*stats_ptr).packets_inspected.saturating_add(1);
            if result == ACTION_DROP {
                (*stats_ptr).packets_dropped = (*stats_ptr).packets_dropped.saturating_add(1);
            }
        }
    }
    result
}

fn inspect_packet(ctx: &SkBuffContext) -> i32 {
    let len = ctx.len() as usize;
    if len < IPV4_MIN_HLEN + TCP_MIN_HLEN {
        return ACTION_ALLOW;
    }

    let ver_ihl: u8 = match ctx.load(0) {
        Ok(v) => v,
        Err(_) => return ACTION_ALLOW,
    };
    if (ver_ihl >> 4) != 4 {
        return ACTION_ALLOW;
    }

    let ip_hlen = ((ver_ihl & 0x0F) as usize) * 4;
    if ip_hlen < IPV4_MIN_HLEN || ip_hlen > len {
        return ACTION_ALLOW;
    }

    let protocol: u8 = match ctx.load(9) {
        Ok(p) => p,
        Err(_) => return ACTION_ALLOW,
    };
    if protocol != PROTO_TCP {
        return ACTION_ALLOW;
    }

    let tcp_offset = ip_hlen;
    if tcp_offset + TCP_MIN_HLEN > len {
        return ACTION_ALLOW;
    }

    let tcp_data_offset: u8 = match ctx.load(tcp_offset + 12) {
        Ok(b) => b,
        Err(_) => return ACTION_ALLOW,
    };
    let tcp_hlen = ((tcp_data_offset >> 4) as usize) * 4;
    if tcp_hlen < TCP_MIN_HLEN {
        return ACTION_ALLOW;
    }

    let payload_offset = tcp_offset + tcp_hlen;
    if payload_offset >= len {
        return ACTION_ALLOW;
    }

    let avail = len - payload_offset;
    let scan_len = if avail < INSPECTION_WINDOW { avail } else { INSPECTION_WINDOW };
    if scan_len < 4 {
        return ACTION_ALLOW;
    }

    let b0 = ctx.load(payload_offset).unwrap_or(0);
    let b1 = ctx.load(payload_offset + 1).unwrap_or(0);
    let b2 = ctx.load(payload_offset + 2).unwrap_or(0);
    let b3 = ctx.load(payload_offset + 3).unwrap_or(0);

    if b0 == b'@' && b3 == b'\t' {
        if (b1 == b'H' && b2 == b'D') || (b1 == b'S' && b2 == b'Q') || (b1 == b'R' && b2 == b'G') {
            return ACTION_DROP;
        }
    }
    ACTION_ALLOW
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
CAT_EOF

# 6. Userspace Daemon & Integration Worker
mkdir -p src/bin tests
cat << 'CAT_EOF' > src/main.rs
use anyhow::Result;

fn main() -> Result<()> {
    println!("BeaconZero Daemon (eBPF LSM & Cgroup Net Guard)");
    Ok(())
}
CAT_EOF

# 7. Commit & Push
git add .
git commit -m "feat(core): implement Wasm tabix planner, eBPF LSM confinement, and cgroup egress filter"
git push

echo "[+] Successfully pushed core implementations to GitHub!"
