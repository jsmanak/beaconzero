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
