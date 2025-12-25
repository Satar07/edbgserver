#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DataT {
    pub tid: u32,
    pub pid: u32,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub fault_addr: u64,
    pub event_source: EdbgSource,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdbgSource {
    Uprobe,
    PerfEvent,
}

#[repr(C, u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadFilter {
    None,
    Some(u32),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DataT {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadFilter {}
