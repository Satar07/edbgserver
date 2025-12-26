use anyhow::{Result, anyhow, bail};
use capstone::{
    Capstone, RegId,
    arch::x86::{X86Insn, X86InsnGroup, X86OperandType, X86Reg},
    prelude::*,
};
use edbgserver_common::DataT;
use log::{debug, error, info, trace, warn};

use crate::target::EdbgTarget;

impl EdbgTarget {
    pub fn single_step_thread(&mut self, curr_pc: u64) -> Result<()> {
        debug!("Current PC: {:#x}", curr_pc);

        let next_pc = self
            .calculation_next_pc(curr_pc)
            .map_err(|e| anyhow!("Failed to calculate next PC for x86_64 single step: {}", e))?;

        debug!("Calculated Next PC: {:#x}", next_pc);

        if self.active_sw_breakpoints.contains_key(&next_pc) {
            info!(
                "Next PC {:#x} already has a SW breakpoint, skipping set.",
                next_pc
            );
            return Ok(());
        }

        match self.internel_attach_uprobe(next_pc) {
            Ok(link_id) => {
                info!("Successfully attached UProbe at {:#x}", next_pc);
                self.temp_step_breakpoints = Some((next_pc, link_id));
            }
            Err(e) => {
                warn!(
                    "Failed to attach UProbe at {:#x}: {}. Checking for special cases...",
                    next_pc, e
                );
                if next_pc == curr_pc {
                    bail!(
                        "Stuck in a loop: Cannot attach breakpoint at {:#x} and next PC is same.",
                        next_pc
                    );
                }
                info!(
                    "Skipping un-attachable instruction at {:#x}, recursively stepping...",
                    next_pc
                );
                self.single_step_thread(next_pc)?;
            }
        }
        Ok(())
    }

    fn create_capstone() -> Result<Capstone> {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to create Capstone for x64: {}", e))
    }

    fn read_instruction_buf(&self, pc: u64) -> Result<[u8; 15]> {
        let mut buf = [0u8; 15];
        use process_memory::{CopyAddress, TryIntoProcessHandle};
        let pid = self.get_pid()?;
        // trace!("[ReadMem] Reading 15 bytes from PID {} at {:#x}", pid, pc);
        let handle = (pid as i32).try_into_process_handle()?;
        handle.copy_address(pc as usize, &mut buf)?;
        Ok(buf)
    }

    pub fn calculation_next_pc(&self, current_pc: u64) -> Result<u64> {
        let code_buf = self.read_instruction_buf(current_pc)?;
        let cs = Self::create_capstone()?;
        let insns = cs.disasm_count(&code_buf, current_pc, 1)?;

        let insn = insns
            .first()
            .ok_or(anyhow!("Failed to disassemble at {:#x}", current_pc))?;
        let detail = cs.insn_detail(insn)?;

        debug!(
            "CalcNextPC {:#x}: {} {}",
            current_pc,
            insn.mnemonic().unwrap_or("???"),
            insn.op_str().unwrap_or("???")
        );

        let is_control_flow = detail.groups().iter().any(|&g| {
            let gid = g.0 as u32;
            gid == X86InsnGroup::X86_GRP_JUMP
                || gid == X86InsnGroup::X86_GRP_CALL
                || gid == X86InsnGroup::X86_GRP_RET
                || gid == X86InsnGroup::X86_GRP_IRET
        });

        let next_inst_addr = insn.address() + insn.len() as u64;

        if !is_control_flow {
            trace!(
                "Not control flow, sequential execution -> {:#x}",
                next_inst_addr
            );
            return Ok(next_inst_addr);
        }

        let arch_detail = detail.arch_detail();
        let x86_detail = arch_detail.x86().ok_or_else(|| anyhow!("Not x86 detail"))?;
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| anyhow!("fail to get context"))?;

        let insn_id = X86Insn::from(insn.id().0);

        match insn_id {
            X86Insn::X86_INS_RET | X86Insn::X86_INS_RETF | X86Insn::X86_INS_IRET => {
                let mut stack_buf = [0u8; 8];
                use process_memory::{CopyAddress, TryIntoProcessHandle};
                let handle = (self.get_pid()? as i32).try_into_process_handle()?;
                handle.copy_address(context.rsp as usize, &mut stack_buf)?;
                let ret_addr = u64::from_le_bytes(stack_buf);
                debug!(
                    "RET instruction. Reading stack at {:#x} -> Return Address: {:#x}",
                    context.rsp, ret_addr
                );
                Ok(ret_addr)
            }
            X86Insn::X86_INS_JMP | X86Insn::X86_INS_CALL => {
                let op = x86_detail
                    .operands()
                    .next()
                    .ok_or(anyhow!("No operand for JMP/CALL"))?;
                debug!("Unconditional JMP/CALL. Operand Type: {:?}", op.op_type);

                match op.op_type {
                    X86OperandType::Imm(addr) => {
                        debug!("Target is Immediate: {:#x}", addr);
                        Ok(addr as u64)
                    }
                    X86OperandType::Reg(reg_id) => {
                        let target = get_reg_from_context(reg_id, context)?;
                        debug!("Target is Register {:?}: {:#x}", reg_id, target);
                        Ok(target)
                    }
                    X86OperandType::Mem(mem) => {
                        debug!("Calculating Indirect Jump target from Mem: {:?}", mem);
                        let mut target_ptr_addr = mem.disp() as u64;
                        if mem.base().0 != 0 {
                            let base_reg = mem.base().0 as u32;
                            if base_reg == X86Reg::X86_REG_RIP {
                                target_ptr_addr = target_ptr_addr.wrapping_add(next_inst_addr);
                                debug!(
                                    "RIP-relative addressing. Base: RIP, Disp: {:#x}, Effective Addr: {:#x}",
                                    mem.disp(),
                                    target_ptr_addr
                                );
                            } else {
                                let val = get_reg_from_context(mem.base(), context)?;
                                target_ptr_addr = target_ptr_addr.wrapping_add(val);
                            }
                        }
                        if mem.index().0 != 0 {
                            let index_val = get_reg_from_context(mem.index(), context)?;
                            let scale = mem.scale() as u64;
                            target_ptr_addr =
                                target_ptr_addr.wrapping_add(index_val.wrapping_mul(scale));
                        }

                        debug!("Indirect Jump Pointer Address: {:#x}", target_ptr_addr);

                        let mut ptr_buf = [0u8; 8];
                        use process_memory::{CopyAddress, TryIntoProcessHandle};
                        let handle = (self.get_pid()? as i32).try_into_process_handle()?;

                        match handle.copy_address(target_ptr_addr as usize, &mut ptr_buf) {
                            Ok(_) => {
                                let final_target = u64::from_le_bytes(ptr_buf);
                                debug!(
                                    "Read memory at {:#x} -> Target: {:#x}",
                                    target_ptr_addr, final_target
                                );
                                Ok(final_target)
                            }
                            Err(e) => {
                                error!(
                                    "Failed to read jump target from memory at {:#x}: {}",
                                    target_ptr_addr, e
                                );
                                Err(anyhow!("Failed to read indirect jump target: {}", e))
                            }
                        }
                    }
                    _ => bail!("Unsupported JMP/CALL operand type: {:?}", op.op_type),
                }
            }
            id if is_jcc(id) => {
                let condition_met = check_x86_condition(id, context.eflags);
                debug!(
                    "Conditional Jump ({:?}). RFLAGS: {:#x}. Condition Met: {}",
                    id, context.eflags, condition_met
                );

                if condition_met {
                    let op = x86_detail
                        .operands()
                        .next()
                        .ok_or(anyhow!("No operand for Jcc"))?;
                    if let X86OperandType::Imm(addr) = op.op_type {
                        debug!("Condition met, jumping to {:#x}", addr);
                        return Ok(addr as u64);
                    }
                    warn!("Jcc taken but operand is not Imm? {:?}", op.op_type);
                } else {
                    debug!(
                        "Condition NOT met, falling through to {:#x}",
                        next_inst_addr
                    );
                }
                Ok(next_inst_addr)
            }
            _ => {
                error!(
                    "Unsupported control flow x86 instruction: {:?} at {:#x}",
                    insn.id(),
                    insn.address()
                );
                Ok(next_inst_addr)
            }
        }
    }
}

fn is_jcc(id: X86Insn) -> bool {
    matches!(
        id,
        X86Insn::X86_INS_JE
            | X86Insn::X86_INS_JNE
            | X86Insn::X86_INS_JG
            | X86Insn::X86_INS_JGE
            | X86Insn::X86_INS_JL
            | X86Insn::X86_INS_JLE
            | X86Insn::X86_INS_JA
            | X86Insn::X86_INS_JAE
            | X86Insn::X86_INS_JB
            | X86Insn::X86_INS_JBE
    )
}

fn check_x86_condition(insn: X86Insn, rflags: u64) -> bool {
    let zf = (rflags >> 6) & 1 == 1;
    let cf = rflags & 1 == 1;
    let sf = (rflags >> 7) & 1 == 1;
    let of = (rflags >> 11) & 1 == 1;

    match insn {
        X86Insn::X86_INS_JE => zf,
        X86Insn::X86_INS_JNE => !zf,
        X86Insn::X86_INS_JG => !zf && (sf == of),
        X86Insn::X86_INS_JGE => sf == of,
        X86Insn::X86_INS_JL => sf != of,
        X86Insn::X86_INS_JLE => zf || (sf != of),
        X86Insn::X86_INS_JA => !cf && !zf,
        X86Insn::X86_INS_JAE => !cf,
        X86Insn::X86_INS_JB => cf,
        X86Insn::X86_INS_JBE => cf || zf,
        _ => true,
    }
}

fn get_reg_from_context(reg_id: RegId, context: &DataT) -> Result<u64> {
    let id = reg_id.0 as u32;

    match id {
        X86Reg::X86_REG_CS => Ok(context.cs),
        X86Reg::X86_REG_SS => Ok(context.ss),
        X86Reg::X86_REG_EFLAGS => Ok(context.eflags),

        // --- 64-bit Registers ---
        X86Reg::X86_REG_RAX => Ok(context.rax),
        X86Reg::X86_REG_RBX => Ok(context.rbx),
        X86Reg::X86_REG_RCX => Ok(context.rcx),
        X86Reg::X86_REG_RDX => Ok(context.rdx),
        X86Reg::X86_REG_RDI => Ok(context.rdi),
        X86Reg::X86_REG_RSI => Ok(context.rsi),
        X86Reg::X86_REG_RBP => Ok(context.rbp),
        X86Reg::X86_REG_RSP => Ok(context.rsp),
        X86Reg::X86_REG_RIP => Ok(context.rip),
        X86Reg::X86_REG_R8 => Ok(context.r8),
        X86Reg::X86_REG_R9 => Ok(context.r9),
        X86Reg::X86_REG_R10 => Ok(context.r10),
        X86Reg::X86_REG_R11 => Ok(context.r11),
        X86Reg::X86_REG_R12 => Ok(context.r12),
        X86Reg::X86_REG_R13 => Ok(context.r13),
        X86Reg::X86_REG_R14 => Ok(context.r14),
        X86Reg::X86_REG_R15 => Ok(context.r15),

        // --- 32-bit Registers (EAX, EBX, etc.) ---
        X86Reg::X86_REG_EAX => Ok(context.rax as u32 as u64),
        X86Reg::X86_REG_EBX => Ok(context.rbx as u32 as u64),
        X86Reg::X86_REG_ECX => Ok(context.rcx as u32 as u64),
        X86Reg::X86_REG_EDX => Ok(context.rdx as u32 as u64),
        X86Reg::X86_REG_EDI => Ok(context.rdi as u32 as u64),
        X86Reg::X86_REG_ESI => Ok(context.rsi as u32 as u64),
        X86Reg::X86_REG_EBP => Ok(context.rbp as u32 as u64),
        X86Reg::X86_REG_ESP => Ok(context.rsp as u32 as u64),
        X86Reg::X86_REG_R8D => Ok(context.r8 as u32 as u64),
        X86Reg::X86_REG_R9D => Ok(context.r9 as u32 as u64),
        X86Reg::X86_REG_R10D => Ok(context.r10 as u32 as u64),
        X86Reg::X86_REG_R11D => Ok(context.r11 as u32 as u64),
        X86Reg::X86_REG_R12D => Ok(context.r12 as u32 as u64),
        X86Reg::X86_REG_R13D => Ok(context.r13 as u32 as u64),
        X86Reg::X86_REG_R14D => Ok(context.r14 as u32 as u64),
        X86Reg::X86_REG_R15D => Ok(context.r15 as u32 as u64),

        // --- 16-bit Registers (AX, BX, etc.) ---
        X86Reg::X86_REG_AX => Ok(context.rax as u16 as u64),
        X86Reg::X86_REG_BX => Ok(context.rbx as u16 as u64),
        X86Reg::X86_REG_CX => Ok(context.rcx as u16 as u64),
        X86Reg::X86_REG_DX => Ok(context.rdx as u16 as u64),
        X86Reg::X86_REG_R8W => Ok(context.r8 as u16 as u64),
        X86Reg::X86_REG_R9W => Ok(context.r9 as u16 as u64),
        X86Reg::X86_REG_R10W => Ok(context.r10 as u16 as u64),
        X86Reg::X86_REG_R11W => Ok(context.r11 as u16 as u64),
        X86Reg::X86_REG_R12W => Ok(context.r12 as u16 as u64),
        X86Reg::X86_REG_R13W => Ok(context.r13 as u16 as u64),
        X86Reg::X86_REG_R14W => Ok(context.r14 as u16 as u64),
        X86Reg::X86_REG_R15W => Ok(context.r15 as u16 as u64),

        // --- 8-bit Low Registers (AL, BL, CL, DL, SIL, DIL, BPL, SPL) ---
        X86Reg::X86_REG_AL => Ok(context.rax as u8 as u64),
        X86Reg::X86_REG_BL => Ok(context.rbx as u8 as u64),
        X86Reg::X86_REG_CL => Ok(context.rcx as u8 as u64),
        X86Reg::X86_REG_DL => Ok(context.rdx as u8 as u64),
        X86Reg::X86_REG_SIL => Ok(context.rsi as u8 as u64),
        X86Reg::X86_REG_DIL => Ok(context.rdi as u8 as u64),
        X86Reg::X86_REG_BPL => Ok(context.rbp as u8 as u64),
        X86Reg::X86_REG_SPL => Ok(context.rsp as u8 as u64),
        X86Reg::X86_REG_R8B => Ok(context.r8 as u8 as u64),
        X86Reg::X86_REG_R9B => Ok(context.r9 as u8 as u64),
        X86Reg::X86_REG_R10B => Ok(context.r10 as u8 as u64),
        X86Reg::X86_REG_R11B => Ok(context.r11 as u8 as u64),
        X86Reg::X86_REG_R12B => Ok(context.r12 as u8 as u64),
        X86Reg::X86_REG_R13B => Ok(context.r13 as u8 as u64),
        X86Reg::X86_REG_R14B => Ok(context.r14 as u8 as u64),
        X86Reg::X86_REG_R15B => Ok(context.r15 as u8 as u64),

        // --- 8-bit High Registers (AH, BH, CH, DH) ---
        X86Reg::X86_REG_AH => Ok((context.rax >> 8) as u8 as u64),
        X86Reg::X86_REG_BH => Ok((context.rbx >> 8) as u8 as u64),
        X86Reg::X86_REG_CH => Ok((context.rcx >> 8) as u8 as u64),
        X86Reg::X86_REG_DH => Ok((context.rdx >> 8) as u8 as u64),

        _ => bail!("Unsupported or unmapped x86 register id: {}", id),
    }
}
