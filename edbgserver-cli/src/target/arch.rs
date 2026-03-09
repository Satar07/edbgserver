#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub type TargetArch = aarch64::LinuxAArch64Core;
#[cfg(target_arch = "aarch64")]
pub use aarch64::fill_regs;
#[cfg(target_arch = "aarch64")]
pub use aarch64::fill_regs_minimal;

#[cfg(target_arch = "x86_64")]
pub type TargetArch = gdbstub_arch::x86::X86_64_SSE;
#[cfg(target_arch = "x86_64")]
pub use x86_64::fill_regs;
#[cfg(target_arch = "x86_64")]
pub use x86_64::fill_regs_minimal;
