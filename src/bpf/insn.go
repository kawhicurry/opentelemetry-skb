package bpf

import (
	"github.com/cilium/ebpf/asm"
)

func GetInsn(eventFD int, argPos int16, argRet int16, flag int64) asm.Instructions {
	b := insnBuilder{}
	b.insnRingbufReserve(eventFD)
	b.insnSetFlag(flag)
	b.insnGetKtime()
	b.insnGetPid()
	b.insnGetCPU()
	b.insnGetIp()
	if argPos < 0 {
		b.insnSetZero(OFFSET_POSARG)
		b.insnSetZero(OFFSET_TIMESTAMP)
	} else {
		b.insnGetArgSkb(argPos)
	}
	if argRet <= 0 {
		b.insnSetZero(OFFSET_RETARG)
	} else {
		b.insnGetRetSkb()
	}
	b.insnGetStack()
	b.insnRingbufSubmit()
	b.insnReturn()

	// print(b.instrucions.String())
	return b.instrucions
}

func (b *insnBuilder) insnRingbufReserve(eventFD int) {
	insn := asm.Instructions{
		asm.Mov.Reg(RegContext, asm.R1).WithSource(asm.Comment("save ctx")),

		asm.LoadMapPtr(asm.R1, eventFD),
		asm.Mov.Imm(asm.R2, int32(OFFSET_MAX+MaxStackSize)),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, returnSymbol),
		asm.Mov.Reg(RegEvent, asm.R0),
	}
	b.instrucions = append(insn, b.instrucions...)
}

func (b *insnBuilder) insnRingbufSubmit() {
	insn := asm.Instructions{
		asm.Mov.Reg(asm.R1, RegEvent),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
	}
	b.instrucions = append(b.instrucions, insn...)
}
func (b *insnBuilder) insnSetFlag(flag int64) {
	insn := asm.Instructions{
		asm.StoreImm(RegEvent, OFFSET_FLAG, flag, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}
func (b *insnBuilder) insnGetKtime() {
	insn := asm.Instructions{
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(RegEvent, OFFSET_KTIME, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}
func (b *insnBuilder) insnGetPid() {
	insn := asm.Instructions{
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(RegEvent, OFFSET_TPID, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnGetCPU() {
	insn := asm.Instructions{
		asm.FnGetSmpProcessorId.Call(),
		asm.StoreMem(RegEvent, OFFSET_CPU, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnGetIp() {
	insn := asm.Instructions{
		asm.Mov.Reg(asm.R1, RegContext),
		asm.FnGetFuncIp.Call(),
		asm.StoreMem(RegEvent, OFFSET_IP, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnGetArgSkb(argPos int16) {
	timestampOffset := GetSkbTimestampOffset()
	insn := asm.Instructions{
		// asm.LoadMem(asm.R0, RegContext, argPos*8, asm.DWord).WithSource(asm.Comment("read from ctx[pos]")),
		// asm.StoreMem(RegEvent, OFFSET_POSARG, asm.R0, asm.DWord),
		asm.StoreImm(asm.R10, -8, 0, asm.DWord),
		// asm.StoreImm(asm.R10, -16, 0, asm.DWord),

		asm.Mov.Reg(asm.R1, RegContext),
		asm.LoadImm(asm.R2, int64(argPos), asm.DWord),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(asm.R0, asm.R10, -8, asm.DWord),
		asm.StoreMem(RegEvent, OFFSET_POSARG, asm.R0, asm.DWord),

		asm.Mov.Reg(asm.R1, asm.R10),
		asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Add.Imm(asm.R3, int32(timestampOffset)),
		asm.FnProbeRead.Call(),
		// asm.LoadMem(asm.R1, asm.R0, int16(timestampOffset), asm.DWord),
		// asm.Add.Reg(asm.R0, RegTmp),
		asm.LoadMem(asm.R0, asm.R10, -8, asm.DWord),
		asm.StoreMem(RegEvent, OFFSET_TIMESTAMP, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnGetRetSkb() {
	insn := asm.Instructions{
		// asm.LoadMem(asm.R0, RegContext, argRet*8, asm.DWord).WithSource(asm.Comment("read from ctx[0]")),
		asm.Mov.Reg(asm.R1, RegContext),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8),
		asm.StoreImm(asm.R10, -8, 0, asm.DWord),
		asm.FnGetFuncRet.Call(),
		asm.LoadMem(asm.R0, asm.R10, -8, asm.DWord),
		asm.StoreMem(RegEvent, OFFSET_RETARG, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnSetZero(offset int16) {
	insn := asm.Instructions{
		asm.StoreImm(RegEvent, offset, 0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnGetStack() {
	insn := asm.Instructions{
		asm.Mov.Reg(asm.R1, RegContext),
		asm.Mov.Reg(asm.R2, RegEvent),
		asm.Add.Imm(asm.R2, int32(OFFSET_STACKTRACE)),
		asm.Mov.Imm(asm.R3, MaxStackSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnGetStack.Call(),

		// asm.LoadMem(asm.R0, asm.R6, 0, asm.DWord),
		asm.StoreMem(RegEvent, OFFSET_STACKSIZE, asm.R0, asm.DWord),
	}
	b.instrucions = append(b.instrucions, insn...)
}

func (b *insnBuilder) insnReturn() {
	insn := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol(returnSymbol),
		asm.Return(),
	}
	b.instrucions = append(b.instrucions, insn...)
}
