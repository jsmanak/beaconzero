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
