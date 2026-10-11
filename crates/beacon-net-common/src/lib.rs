#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterStats {
    pub packets_inspected: u64,
    pub packets_dropped: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterStats {}
