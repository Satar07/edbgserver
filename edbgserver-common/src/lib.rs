#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DataT {
    pub pid: u32,
    pub tgid: u32,
    pub regs: [u64; 31], //user_pt_regs struct for arm64
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DataT {}
