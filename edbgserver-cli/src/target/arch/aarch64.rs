use anyhow::{Result, anyhow, bail};
use capstone::{
    arch::arm64::{Arm64CC, Arm64Insn, Arm64InsnGroup, Arm64OperandType, Arm64Reg},
    prelude::*,
};
use edbgserver_common::DataT;
use gdbstub::{
    common::Tid,
    target::{TargetError, TargetResult, ext::base::single_register_access::SingleRegisterAccess},
};
use log::{debug, error, warn};

use crate::target::EdbgTarget;

pub struct LinuxAArch64Core {}

impl gdbstub::arch::Arch for LinuxAArch64Core {
    type BreakpointKind = usize;
    type RegId = gdbstub_arch::aarch64::reg::id::AArch64RegId;
    type Registers = AArch64MinimalRegs;
    type Usize = u64;

    fn target_description_xml() -> Option<&'static str> {
        static DESCRIPTION_XML: &str = concat!(
            r#"<target version="1.0">"#,
            "<architecture>aarch64</architecture>",
            "<osabi>GNU/Linux</osabi>",
            include_str!("aarch64_core.xml"),
            "</target>",
        );

        Some(DESCRIPTION_XML)
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct AArch64MinimalRegs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
}

impl gdbstub::arch::Registers for AArch64MinimalRegs {
    type ProgramCounter = u64;

    fn pc(&self) -> Self::ProgramCounter {
        self.pc
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        macro_rules! write_bytes {
            ($var: expr) => {
                for b in $var.to_le_bytes() {
                    write_byte(Some(b))
                }
            };
        }
        for reg in self.x.iter() {
            write_bytes!(reg);
        }
        write_bytes!(self.sp);
        write_bytes!(self.pc);
        write_bytes!(self.cpsr);
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        const CPSR_OFF: usize = core::mem::size_of::<u64>() * 33;
        const END: usize = CPSR_OFF + core::mem::size_of::<u32>() * 2;

        if bytes.len() < END {
            return Err(());
        }

        let mut regs = bytes[0..CPSR_OFF]
            .chunks_exact(core::mem::size_of::<u64>())
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()));

        for reg in self.x.iter_mut() {
            *reg = regs.next().ok_or(())?
        }
        self.sp = regs.next().ok_or(())?;
        self.pc = regs.next().ok_or(())?;

        let mut regs = bytes[CPSR_OFF..]
            .chunks_exact(core::mem::size_of::<u32>())
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()));

        self.cpsr = regs.next().ok_or(())?;
        Ok(())
    }
}

pub fn fill_regs(regs: &mut AArch64MinimalRegs, ctx: &DataT) {
    regs.x = ctx.regs;
    regs.pc = ctx.pc;
    regs.sp = ctx.sp;
    regs.cpsr = ctx.pstate as u32;
}

impl SingleRegisterAccess<Tid> for EdbgTarget {
    fn read_register(
        &mut self,
        tid: Tid,
        reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let ctx = match &self.context {
            Some(c) if !self.is_multi_thread || c.tid == tid.get() as u32 => c,
            _ => {
                warn!("read_register: no context with tid {}", tid.get());
                return Ok(0);
            }
        };

        match reg_id {
            gdbstub_arch::aarch64::reg::id::AArch64RegId::X(n) => {
                buf.copy_from_slice(&ctx.regs[n as usize].to_le_bytes());
                Ok(8)
            }
            gdbstub_arch::aarch64::reg::id::AArch64RegId::Sp => {
                buf.copy_from_slice(&ctx.sp.to_le_bytes());
                Ok(8)
            }
            gdbstub_arch::aarch64::reg::id::AArch64RegId::Pc => {
                buf.copy_from_slice(&ctx.pc.to_le_bytes());
                Ok(8)
            }
            gdbstub_arch::aarch64::reg::id::AArch64RegId::Pstate => {
                buf.copy_from_slice(&ctx.pstate.to_le_bytes());
                Ok(8)
            }
            _ => Ok(0),
        }
    }

    fn write_register(
        &mut self,
        _tid: Tid,
        _reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        _val: &[u8],
    ) -> TargetResult<(), Self> {
        warn!("write single register not fully implemented (requires ptrace or inline hooking)");
        Err(TargetError::NonFatal)
    }
}

impl EdbgTarget {
    fn create_capstone() -> Result<Capstone> {
        Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to create Capstone instance: {}", e))
    }

    fn read_instruction(&self, pc: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        use process_memory::{CopyAddress, TryIntoProcessHandle};
        let handle = (self.get_pid()? as i32).try_into_process_handle()?;
        handle.copy_address(pc as usize, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn calculation_next_pc(&self, current_pc: u64) -> Result<u64> {
        debug!("Calculating next PC from current PC: {:#x}", current_pc);
        let code = self.read_instruction(current_pc)?;
        let code_byte = code.to_le_bytes();
        let cs = EdbgTarget::create_capstone()?;
        let insn = cs.disasm_count(&code_byte, current_pc, 1)?;
        if insn.is_empty() {
            bail!("Failed to disassemble instruction at {:#x}", current_pc);
        }
        let insn = insn.first().ok_or(anyhow!("Failed to get instruction"))?;
        debug!(
            "CalcNextPC {:#x}: {} {}",
            current_pc,
            insn.mnemonic().unwrap_or("???"),
            insn.op_str().unwrap_or("???")
        );
        let detail = cs.insn_detail(insn)?;
        let groups = detail.groups();
        let is_control_flow = groups.iter().any(|&g| {
            matches!(
                g.0 as u32,
                Arm64InsnGroup::ARM64_GRP_JUMP
                    | Arm64InsnGroup::ARM64_GRP_CALL
                    | Arm64InsnGroup::ARM64_GRP_RET
                    | Arm64InsnGroup::ARM64_GRP_BRANCH_RELATIVE
            )
        });

        if !is_control_flow {
            return Ok(insn.address() + insn.len() as u64);
        }

        let inst_id = insn.id().0;
        let insn_enum = Arm64Insn::from(inst_id);
        let arch_detail = detail.arch_detail();
        let arm64_detail = arch_detail.arm64().unwrap();
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| anyhow!("fail to get context"))?;
        match insn_enum {
            // bl label | b lable
            Arm64Insn::ARM64_INS_B | Arm64Insn::ARM64_INS_BL => {
                let cc = arm64_detail.cc();
                let pstate = context.pstate;
                if !check_condition(cc, pstate) {
                    return Ok(insn.address() + insn.len() as u64);
                }
                if let Some(op) = arm64_detail.operands().next()
                    && let Arm64OperandType::Imm(target) = op.op_type
                {
                    return Ok(target as u64);
                }
                bail!("Failed to get target for B or BL");
            }
            // br x8 | blr x8 | ret
            Arm64Insn::ARM64_INS_BR | Arm64Insn::ARM64_INS_BLR => {
                let op = arm64_detail.operands().next().unwrap();
                let reg_id = match op.op_type {
                    Arm64OperandType::Reg(reg_id) => reg_id,
                    _ => bail!("Expected register operand for BR/BLR/RET"),
                };
                let res = get_reg_from_context(reg_id, context)?;
                Ok(res)
            }
            Arm64Insn::ARM64_INS_RET => {
                let link_reg = context.regs[30]; // LR is X30
                Ok(link_reg)
            }
            // cbz x0, label | cbnz x0, label
            Arm64Insn::ARM64_INS_CBZ | Arm64Insn::ARM64_INS_CBNZ => {
                let ops: Vec<_> = arm64_detail.operands().collect();
                if ops.len() < 2 {
                    bail!("Invalid CBZ/CBNZ operands")
                }
                let test_val = if let Arm64OperandType::Reg(reg_id) = ops[0].op_type {
                    get_reg_from_context(reg_id, context)?
                } else {
                    bail!("CBZ op1 not reg")
                };

                let test_res_z = test_val == 0;
                let target = if let Arm64OperandType::Imm(addr) = ops[1].op_type {
                    addr as u64
                } else {
                    bail!("CBZ op2 not imm")
                };

                let is_cbz = matches!(insn_enum, Arm64Insn::ARM64_INS_CBZ);
                if (is_cbz && test_res_z) || (!is_cbz && !test_res_z) {
                    Ok(target)
                } else {
                    Ok(insn.address() + insn.len() as u64)
                }
            }
            // tbz Rn, #imm, label | tbnz Rn, #imm, label
            Arm64Insn::ARM64_INS_TBZ | Arm64Insn::ARM64_INS_TBNZ => {
                let ops: Vec<_> = arm64_detail.operands().collect();
                if ops.len() < 3 {
                    bail!("Invalid TBZ/TBNZ operands")
                }
                let val = if let Arm64OperandType::Reg(reg_id) = ops.first().unwrap().op_type {
                    get_reg_from_context(reg_id, context)?
                } else {
                    bail!("TBZ op0 not reg");
                };

                let bit = if let Arm64OperandType::Imm(b) = ops[1].op_type {
                    b as u64
                } else {
                    bail!("TBZ op1 not imm")
                };

                // Op2: Target (Imm)
                let target = if let Arm64OperandType::Imm(addr) = ops[2].op_type {
                    addr as u64
                } else {
                    bail!("TBZ op2 not imm")
                };

                let bit_set_z = (val >> bit) & 1 == 0;
                let is_tbz = insn_enum == Arm64Insn::ARM64_INS_TBZ;
                if (is_tbz && bit_set_z) || (!is_tbz && !bit_set_z) {
                    Ok(target)
                } else {
                    Ok(insn.address() + insn.len() as u64)
                }
            }
            _ => {
                error!(
                    "Unsupported control flow instruction: {:?} at {:#x}",
                    insn_enum,
                    insn.address()
                );
                Ok(insn.address() + insn.len() as u64)
            }
        }
    }
}

fn check_condition(cc: Arm64CC, pstate: u64) -> bool {
    let n = (pstate >> 31) & 1 == 1;
    let z = (pstate >> 30) & 1 == 1;
    let c = (pstate >> 29) & 1 == 1;
    let v = (pstate >> 28) & 1 == 1;

    match cc {
        Arm64CC::ARM64_CC_EQ => z,              // Equal
        Arm64CC::ARM64_CC_NE => !z,             // Not Equal
        Arm64CC::ARM64_CC_HS => c,              // Unsigned higher or same (CS)
        Arm64CC::ARM64_CC_LO => !c,             // Unsigned lower (CC)
        Arm64CC::ARM64_CC_MI => n,              // Minus (Negative)
        Arm64CC::ARM64_CC_PL => !n,             // Plus (Positive or Zero)
        Arm64CC::ARM64_CC_VS => v,              // Overflow
        Arm64CC::ARM64_CC_VC => !v,             // No Overflow
        Arm64CC::ARM64_CC_HI => c && !z,        // Unsigned higher
        Arm64CC::ARM64_CC_LS => !c || z,        // Unsigned lower or same
        Arm64CC::ARM64_CC_GE => n == v,         // Signed greater or equal
        Arm64CC::ARM64_CC_LT => n != v,         // Signed less than
        Arm64CC::ARM64_CC_GT => !z && (n == v), // Signed greater than
        Arm64CC::ARM64_CC_LE => z || (n != v),  // Signed less or equal
        Arm64CC::ARM64_CC_AL => true,           // Always
        Arm64CC::ARM64_CC_NV => true, // Always (historically "Never", but behaves as AL in A64)
        Arm64CC::ARM64_CC_INVALID => true, // No condition specified, so always
    }
}

fn get_reg_from_context(reg_id: RegId, context: &DataT) -> Result<u64> {
    let reg_id = reg_id.0 as u32;
    let res = match reg_id {
        Arm64Reg::ARM64_REG_X0 => context.regs[0],
        Arm64Reg::ARM64_REG_X1 => context.regs[1],
        Arm64Reg::ARM64_REG_X2 => context.regs[2],
        Arm64Reg::ARM64_REG_X3 => context.regs[3],
        Arm64Reg::ARM64_REG_X4 => context.regs[4],
        Arm64Reg::ARM64_REG_X5 => context.regs[5],
        Arm64Reg::ARM64_REG_X6 => context.regs[6],
        Arm64Reg::ARM64_REG_X7 => context.regs[7],
        Arm64Reg::ARM64_REG_X8 => context.regs[8],
        Arm64Reg::ARM64_REG_X9 => context.regs[9],
        Arm64Reg::ARM64_REG_X10 => context.regs[10],
        Arm64Reg::ARM64_REG_X11 => context.regs[11],
        Arm64Reg::ARM64_REG_X12 => context.regs[12],
        Arm64Reg::ARM64_REG_X13 => context.regs[13],
        Arm64Reg::ARM64_REG_X14 => context.regs[14],
        Arm64Reg::ARM64_REG_X15 => context.regs[15],
        Arm64Reg::ARM64_REG_X16 => context.regs[16],
        Arm64Reg::ARM64_REG_X17 => context.regs[17],
        Arm64Reg::ARM64_REG_X18 => context.regs[18],
        Arm64Reg::ARM64_REG_X19 => context.regs[19],
        Arm64Reg::ARM64_REG_X20 => context.regs[20],
        Arm64Reg::ARM64_REG_X21 => context.regs[21],
        Arm64Reg::ARM64_REG_X22 => context.regs[22],
        Arm64Reg::ARM64_REG_X23 => context.regs[23],
        Arm64Reg::ARM64_REG_X24 => context.regs[24],
        Arm64Reg::ARM64_REG_X25 => context.regs[25],
        Arm64Reg::ARM64_REG_X26 => context.regs[26],
        Arm64Reg::ARM64_REG_X27 => context.regs[27],
        Arm64Reg::ARM64_REG_X28 => context.regs[28],
        Arm64Reg::ARM64_REG_X29 => context.regs[29], // FP
        Arm64Reg::ARM64_REG_X30 => context.regs[30], // LR
        Arm64Reg::ARM64_REG_W0 => context.regs[0] as u32 as u64,
        Arm64Reg::ARM64_REG_W1 => context.regs[1] as u32 as u64,
        Arm64Reg::ARM64_REG_W2 => context.regs[2] as u32 as u64,
        Arm64Reg::ARM64_REG_W3 => context.regs[3] as u32 as u64,
        Arm64Reg::ARM64_REG_W4 => context.regs[4] as u32 as u64,
        Arm64Reg::ARM64_REG_W5 => context.regs[5] as u32 as u64,
        Arm64Reg::ARM64_REG_W6 => context.regs[6] as u32 as u64,
        Arm64Reg::ARM64_REG_W7 => context.regs[7] as u32 as u64,
        Arm64Reg::ARM64_REG_W8 => context.regs[8] as u32 as u64,
        Arm64Reg::ARM64_REG_W9 => context.regs[9] as u32 as u64,
        Arm64Reg::ARM64_REG_W10 => context.regs[10] as u32 as u64,
        Arm64Reg::ARM64_REG_W11 => context.regs[11] as u32 as u64,
        Arm64Reg::ARM64_REG_W12 => context.regs[12] as u32 as u64,
        Arm64Reg::ARM64_REG_W13 => context.regs[13] as u32 as u64,
        Arm64Reg::ARM64_REG_W14 => context.regs[14] as u32 as u64,
        Arm64Reg::ARM64_REG_W15 => context.regs[15] as u32 as u64,
        Arm64Reg::ARM64_REG_W16 => context.regs[16] as u32 as u64,
        Arm64Reg::ARM64_REG_W17 => context.regs[17] as u32 as u64,
        Arm64Reg::ARM64_REG_W18 => context.regs[18] as u32 as u64,
        Arm64Reg::ARM64_REG_W19 => context.regs[19] as u32 as u64,
        Arm64Reg::ARM64_REG_W20 => context.regs[20] as u32 as u64,
        Arm64Reg::ARM64_REG_W21 => context.regs[21] as u32 as u64,
        Arm64Reg::ARM64_REG_W22 => context.regs[22] as u32 as u64,
        Arm64Reg::ARM64_REG_W23 => context.regs[23] as u32 as u64,
        Arm64Reg::ARM64_REG_W24 => context.regs[24] as u32 as u64,
        Arm64Reg::ARM64_REG_W25 => context.regs[25] as u32 as u64,
        Arm64Reg::ARM64_REG_W26 => context.regs[26] as u32 as u64,
        Arm64Reg::ARM64_REG_W27 => context.regs[27] as u32 as u64,
        Arm64Reg::ARM64_REG_W28 => context.regs[28] as u32 as u64,
        Arm64Reg::ARM64_REG_W29 => context.regs[29] as u32 as u64,
        Arm64Reg::ARM64_REG_W30 => context.regs[30] as u32 as u64,
        _ => bail!("Unsupported register id: {}", reg_id),
    };
    Ok(res)
}
