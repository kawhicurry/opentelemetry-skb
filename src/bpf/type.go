package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	BPF_F_INDEX_MASK  = 0xffffffff
	BPF_F_CURRENT_CPU = BPF_F_INDEX_MASK

	RegContext = asm.R6
	RegEvent   = asm.R9

	returnSymbol = "return"

	ENTRY_FLAG = 0
	EXIT_FLAG  = 1
)

type RingbufLoader struct {
	ringbuf *ebpf.Map
	reader  *ringbuf.Reader
}
type ProgLoader struct {
	entryProg *ebpf.Program
	exitProg  *ebpf.Program
	entryLink link.Link
	exitLink  link.Link
}

type insnBuilder struct {
	instrucions asm.Instructions
}

type Closer interface {
	Close() error
}

func AnyClose(c Closer) {
	c.Close()
}

const (
	OFFSET_FLAG = int16(iota * 8)
	OFFSET_KTIME
	OFFSET_TPID
	OFFSET_CPU
	OFFSET_IP
	OFFSET_POSARG
	OFFSET_RETARG
	OFFSET_STACKSIZE
	OFFSET_STACKTRACE
	OFFSET_MAX

	MaxStackSize       = 1024
	bpfCurrentCpuMagic = 0xffffffff
)
