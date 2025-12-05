#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_send_signal},
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::{debug, error};
use edbgserver_common::DataT;

const SIGSTOP: u32 = 19;

const RINGBUF_SIZE: u32 = 64 * 1024;
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[uprobe]
pub fn edbgserver(ctx: ProbeContext) -> i64 {
    match try_edbgserver(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "error num: {}", ret);
            ret
        }
    }
}

fn try_edbgserver(ctx: &ProbeContext) -> Result<i64, i64> {
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data_ptr = entry.as_mut_ptr();
        unsafe {
            (*data_ptr).pid = bpf_get_current_pid_tgid() as u32;
            (*data_ptr).tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
            for i in 0..31 {
                (*data_ptr).regs[i] = (*ctx.regs).regs[i];
            }
            (*data_ptr).pc = (*ctx.regs).pc;
            (*data_ptr).sp = (*ctx.regs).sp;
            (*data_ptr).pstate = (*ctx.regs).pstate;
        }
        entry.submit(0);
    } else {
        error!(ctx, "failed to reserve ringbuf space");
    }
    debug!(ctx, "send data to probe array");
    unsafe {
        bpf_send_signal(SIGSTOP);
    }
    debug!(ctx, "sent SIGSTOP to current process");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
