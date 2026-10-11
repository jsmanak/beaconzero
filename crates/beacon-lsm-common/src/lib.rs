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
