package parse

import (
	"opentelemetry-skb/bpf"

	"github.com/cilium/ebpf/ringbuf"
)

func (s *SkbStack) Init() {}

func BuildStackNodeFromRecord(record *ringbuf.Record) SkbStackNode {
	s := SkbStackNode{}
	s.Skb = readRecord(record, bpf.OFFSET_POSARG)
	s.Flag = readRecord(record, bpf.OFFSET_FLAG)
	s.Ktime = readRecord(record, bpf.OFFSET_KTIME)
	s.TPid = readRecord(record, bpf.OFFSET_TPID)
	s.Ret = readRecord(record, bpf.OFFSET_RETARG)
	s.Addr = readRecord(record, bpf.OFFSET_IP)
	curFuncName := KsymsParser.LookupByInstructionPointer(s.Addr)
	// use skip to ignore bpf_prog in stack trace
	skip := true
	length := int16(len(record.RawSample))
	for i := bpf.OFFSET_STACKTRACE; i <= length; i += 8 {
		// curStack := bpf.ByteOrder().Uint64(record.RawSample[i-8 : i])
		curStack := readRecord(record, i)
		stackFuncName := KsymsParser.LookupByInstructionPointer(curStack)
		if curStack == 0 {
			break
		}
		if curFuncName == stackFuncName {
			skip = false
		}
		if skip {
			continue
		}
		s.StackNames = append(s.StackNames, stackFuncName)
	}
	return s
}
