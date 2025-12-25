#![no_std]

#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "bpf", bpf_target_arch = "aarch64")
))]
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

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "bpf", bpf_target_arch = "x86_64")
))]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DataT {
    pub tid: u32,
    pub pid: u32,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub fault_addr: u64,
    pub event_source: EdbgSource,
}

impl DataT {
    #[cfg(target_arch = "aarch64")]
    pub fn pc(&self) -> u64 {
        self.pc
    }
    #[cfg(target_arch = "x86_64")]
    pub fn pc(&self) -> u64 {
        self.rip
    }
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
