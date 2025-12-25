#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_send_signal},
    macros::{map, perf_event, uprobe},
    maps::{Array, RingBuf},
    programs::{PerfEventContext, ProbeContext},
};
use aya_log_ebpf::{debug, error};
use edbgserver_common::{DataT, ThreadFilter};

const SIGSTOP: u32 = 19;

const RINGBUF_SIZE: u32 = 64 * 1024;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[map]
/// index 0: thread id
static THREAD_FILTER: Array<ThreadFilter> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn probe_callback(ctx: ProbeContext) -> i64 {
    match try_probe_callback(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "error num: {}", ret);
            ret
        }
    }
}

#[cfg(any(bpf_target_arch = "aarch64", debug_assertions))]
fn try_probe_callback(ctx: &ProbeContext) -> Result<i64, i64> {
    debug!(ctx, "entered probe callback");
    let current_tid = bpf_get_current_pid_tgid() as u32;
    let filter = THREAD_FILTER.get(0).unwrap_or(&ThreadFilter::None);
    match filter {
        ThreadFilter::None => debug!(ctx, "thread filter is none"),
        ThreadFilter::Some(t) => debug!(ctx, "thread filter tid: {}", *t),
    }
    if let ThreadFilter::Some(tid) = filter
        && *tid != current_tid
    {
        debug!(
            ctx,
            "thread id {} does not match filter {}", current_tid, *tid
        );
        return Ok(0);
    }
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data_ptr = entry.as_mut_ptr();
        let regs = unsafe { &*ctx.regs };
        unsafe {
            (*data_ptr).tid = bpf_get_current_pid_tgid() as u32;
            (*data_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            for i in 0..31 {
                (*data_ptr).regs[i] = regs.regs[i];
            }
            (*data_ptr).pc = regs.pc;
            (*data_ptr).sp = regs.sp;
            (*data_ptr).pstate = regs.pstate;
            (*data_ptr).fault_addr = regs.pc;
            (*data_ptr).event_source = edbgserver_common::EdbgSource::Uprobe;
        }
        entry.submit(0);
    } else {
        error!(ctx, "failed to reserve ringbuf space");
    }
    debug!(ctx, "send data to event array");
    unsafe {
        bpf_send_signal(SIGSTOP);
    }
    debug!(ctx, "sent SIGSTOP to current process");
    Ok(0)
}

#[cfg(bpf_target_arch = "x86_64")]
fn try_probe_callback(ctx: &ProbeContext) -> Result<i64, i64> {
    debug!(ctx, "entered probe callback");
    let current_tid = bpf_get_current_pid_tgid() as u32;
    let filter = THREAD_FILTER.get(0).unwrap_or(&ThreadFilter::None);
    match filter {
        ThreadFilter::None => debug!(ctx, "thread filter is none"),
        ThreadFilter::Some(t) => debug!(ctx, "thread filter tid: {}", *t),
    }
    if let ThreadFilter::Some(tid) = filter
        && *tid != current_tid
    {
        debug!(
            ctx,
            "thread id {} does not match filter {}", current_tid, *tid
        );
        return Ok(0);
    }
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data_ptr = entry.as_mut_ptr();
        let regs = unsafe { *ctx.regs };
        unsafe {
            (*data_ptr).tid = bpf_get_current_pid_tgid() as u32;
            (*data_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*data_ptr).r15 = regs.r15;
            (*data_ptr).r14 = regs.r14;
            (*data_ptr).r13 = regs.r13;
            (*data_ptr).r12 = regs.r12;
            (*data_ptr).rbp = regs.rbp;
            (*data_ptr).rbx = regs.rbx;
            (*data_ptr).r11 = regs.r11;
            (*data_ptr).r10 = regs.r10;
            (*data_ptr).r9 = regs.r9;
            (*data_ptr).r8 = regs.r8;
            (*data_ptr).rax = regs.rax;
            (*data_ptr).rcx = regs.rcx;
            (*data_ptr).rdx = regs.rdx;
            (*data_ptr).rsi = regs.rsi;
            (*data_ptr).rdi = regs.rdi;
            (*data_ptr).rip = regs.rip;
            (*data_ptr).rflags = regs.eflags;
            (*data_ptr).rsp = regs.rsp;
            (*data_ptr).fault_addr = regs.rip;
            (*data_ptr).event_source = edbgserver_common::EdbgSource::Uprobe;
        }
        entry.submit(0);
    } else {
        error!(ctx, "failed to reserve ringbuf space");
    }
    debug!(ctx, "send data to event array");
    unsafe {
        bpf_send_signal(SIGSTOP);
    }
    debug!(ctx, "sent SIGSTOP to current process");
    Ok(0)
}

#[perf_event]
pub fn perf_callback(ctx: PerfEventContext) -> i64 {
    match try_perf_callback(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "error num: {}", ret);
            ret
        }
    }
}

#[cfg(any(bpf_target_arch = "aarch64", debug_assertions))]
fn try_perf_callback(ctx: &PerfEventContext) -> Result<i64, i64> {
    debug!(ctx, "entered perf callback");
    let current_tid = bpf_get_current_pid_tgid() as u32;
    let filter = THREAD_FILTER.get(0).unwrap_or(&ThreadFilter::None);
    if let ThreadFilter::Some(tid) = filter
        && *tid != current_tid
    {
        return Ok(0);
    }
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data_ptr = entry.as_mut_ptr();
        let regs = unsafe { (*ctx.ctx).regs };
        unsafe {
            (*data_ptr).tid = bpf_get_current_pid_tgid() as u32;
            (*data_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            for i in 0..31 {
                (*data_ptr).regs[i] = regs.regs[i];
            }
            (*data_ptr).pc = regs.pc;
            (*data_ptr).sp = regs.sp;
            (*data_ptr).pstate = regs.pstate;
            (*data_ptr).fault_addr = (*ctx.ctx).addr;
            (*data_ptr).event_source = edbgserver_common::EdbgSource::PerfEvent;
        }
        entry.submit(0);
    } else {
        error!(ctx, "failed to reserve ringbuf space");
    }
    debug!(ctx, "send data to event array");
    unsafe {
        bpf_send_signal(SIGSTOP);
    }
    debug!(ctx, "sent SIGSTOP to current process");
    Ok(0)
}

#[cfg(bpf_target_arch = "x86_64")]
fn try_perf_callback(ctx: &PerfEventContext) -> Result<i64, i64> {
    debug!(ctx, "entered perf callback");
    let current_tid = bpf_get_current_pid_tgid() as u32;
    let filter = THREAD_FILTER.get(0).unwrap_or(&ThreadFilter::None);
    if let ThreadFilter::Some(tid) = filter
        && *tid != current_tid
    {
        return Ok(0);
    }
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data_ptr = entry.as_mut_ptr();
        let regs = unsafe { (*ctx.ctx).regs };
        unsafe {
            (*data_ptr).tid = bpf_get_current_pid_tgid() as u32;
            (*data_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*data_ptr).r15 = regs.r15;
            (*data_ptr).r14 = regs.r14;
            (*data_ptr).r13 = regs.r13;
            (*data_ptr).r12 = regs.r12;
            (*data_ptr).rbp = regs.rbp;
            (*data_ptr).rbx = regs.rbx;
            (*data_ptr).r11 = regs.r11;
            (*data_ptr).r10 = regs.r10;
            (*data_ptr).r9 = regs.r9;
            (*data_ptr).r8 = regs.r8;
            (*data_ptr).rax = regs.rax;
            (*data_ptr).rcx = regs.rcx;
            (*data_ptr).rdx = regs.rdx;
            (*data_ptr).rsi = regs.rsi;
            (*data_ptr).rdi = regs.rdi;
            (*data_ptr).rip = regs.rip;
            (*data_ptr).rflags = regs.eflags;
            (*data_ptr).rsp = regs.rsp;
            (*data_ptr).fault_addr = (*ctx.ctx).addr;
            (*data_ptr).event_source = edbgserver_common::EdbgSource::PerfEvent;
        }
        entry.submit(0);
    } else {
        error!(ctx, "failed to reserve ringbuf space");
    }
    debug!(ctx, "send data to event array");
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
