use anyhow::{Result, anyhow, bail};
use capstone::{
    Capstone, RegId,
    arch::x86::{X86Insn, X86InsnGroup, X86OperandType, X86Reg},
    prelude::*,
};
use edbgserver_common::DataT;
use log::{debug, error, info};

use crate::target::EdbgTarget;

impl EdbgTarget {
    pub fn single_step_thread(&mut self, tid: u32, curr_pc: u64) -> Result<()> {
        let next_pc = self
            .calculation_next_pc(curr_pc, tid)
            .map_err(|e| anyhow!("Failed to calculate next PC for x86_64 single step: {}", e))?;

        debug!("Next PC calculated (x86_64): {:#x}", next_pc);

        if self.active_sw_breakpoints.contains_key(&next_pc) {
            return Ok(());
        }

        match self.internel_attach_uprobe(next_pc) {
            Ok(link_id) => {
                info!("Attached UProbe at VMA: {:#x}", next_pc);
                self.temp_step_breakpoints = Some((next_pc, link_id));
            }
            Err(e) => {
                let (is_syscall, insn_len) = {
                    let cs = Self::create_capstone()?;
                    let code = self.read_instruction_buf(next_pc, tid)?;
                    let insns = cs.disasm_count(&code, next_pc, 1)?;
                    let insn = insns.first().ok_or(anyhow!("failed to get first insn"))?;

                    let id = X86Insn::from(insn.id().0);
                    let is_syscall =
                        id == X86Insn::X86_INS_SYSCALL || id == X86Insn::X86_INS_SYSENTER;
                    (is_syscall, insn.len() as u64)
                };

                if is_syscall {
                    info!("Next instruction is SYSCALL, step over");
                    self.single_step_thread(tid, curr_pc + insn_len)?;
                } else {
                    return Err(e);
                }
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

    fn read_instruction_buf(&self, pc: u64, tid: u32) -> Result<[u8; 15]> {
        let mut buf = [0u8; 15];
        use process_memory::{CopyAddress, TryIntoProcessHandle};
        let handle = (tid as i32).try_into_process_handle()?;
        handle.copy_address(pc as usize, &mut buf)?;
        Ok(buf)
    }

    pub fn calculation_next_pc(&self, current_pc: u64, tid: u32) -> Result<u64> {
        debug!(
            "Calculating next PC (x86_64) from current PC: {:#x}",
            current_pc
        );
        let code_buf = self.read_instruction_buf(current_pc, tid)?;
        let cs = Self::create_capstone()?;
        let insns = cs.disasm_count(&code_buf, current_pc, 1)?;

        let insn = insns
            .first()
            .ok_or(anyhow!("Failed to disassemble at {:#x}", current_pc))?;
        let detail = cs.insn_detail(insn)?;

        let is_control_flow = detail.groups().iter().any(|&g| {
            let gid = g.0 as u32;
            gid == X86InsnGroup::X86_GRP_JUMP
                || gid == X86InsnGroup::X86_GRP_CALL
                || gid == X86InsnGroup::X86_GRP_RET
                || gid == X86InsnGroup::X86_GRP_IRET
        });

        let next_inst_addr = insn.address() + insn.len() as u64;

        if !is_control_flow {
            return Ok(next_inst_addr);
        }

        let arch_detail = detail.arch_detail();
        let x86_detail = arch_detail.x86().ok_or_else(|| anyhow!("Not x86 detail"))?;
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| anyhow!("fail to get context"))?;

        match X86Insn::from(insn.id().0) {
            X86Insn::X86_INS_RET | X86Insn::X86_INS_RETF | X86Insn::X86_INS_IRET => {
                let mut stack_buf = [0u8; 8];
                use process_memory::{CopyAddress, TryIntoProcessHandle};
                let handle = (tid as i32).try_into_process_handle()?;
                handle.copy_address(context.rsp as usize, &mut stack_buf)?;
                Ok(u64::from_le_bytes(stack_buf))
            }
            X86Insn::X86_INS_JMP | X86Insn::X86_INS_CALL => {
                let op = x86_detail.operands().next().ok_or(anyhow!("No op"))?;
                match op.op_type {
                    X86OperandType::Imm(addr) => Ok(addr as u64),
                    X86OperandType::Reg(reg_id) => get_reg_from_context(reg_id, context),
                    _ => bail!("Unsupported JMP/CALL operand type"),
                }
            }
            id if is_jcc(id) => {
                if check_x86_condition(id, context.rflags) {
                    let op = x86_detail.operands().next().ok_or(anyhow!("No op"))?;
                    if let X86OperandType::Imm(addr) = op.op_type {
                        return Ok(addr as u64);
                    }
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
    let cf = (rflags >> 0) & 1 == 1;
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
