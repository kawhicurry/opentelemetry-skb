package parse

import (
	"opentelemetry-skb/bpf"
	"opentelemetry-skb/kallsyms"

	"github.com/cilium/ebpf/ringbuf"
)

func readRecord(rc *ringbuf.Record, offset int16) uint64 {
	return bpf.ByteOrder().Uint64(rc.RawSample[offset : offset+8])
}

var rd *kallsyms.KAllSyms

func init() {
	rd, _ = kallsyms.NewKAllSyms()
}

func IngestRecord(record *ringbuf.Record) {
	// rd, _ := kallsyms.NewKAllSyms()

	flag := readRecord(record, bpf.OFFSET_FLAG)
	ktime := readRecord(record, bpf.OFFSET_KTIME)
	tpid := readRecord(record, bpf.OFFSET_TPID)
	cpu := readRecord(record, bpf.OFFSET_CPU)
	addr := readRecord(record, bpf.OFFSET_IP)
	skb := readRecord(record, bpf.OFFSET_POSARG)
	ret := readRecord(record, bpf.OFFSET_RETARG)
	// depth := bpf.ByteOrder().Uint64(record.RawSample[i-8 : i])
	stacks := []uint64{}
	stackNames := []string{}
	funcName := rd.LookupByInstructionPointer(addr)
	skip := true
	length := int16(len(record.RawSample))
	for i := bpf.OFFSET_STACKTRACE; i <= length; i += 8 {
		// curStack := bpf.ByteOrder().Uint64(record.RawSample[i-8 : i])
		curStack := readRecord(record, i)
		stackName := rd.LookupByInstructionPointer(curStack)
		if curStack == 0 {
			break
		}
		if funcName == stackName {
			skip = false
		}
		if skip {
			continue
		}
		stacks = append(stacks, curStack)
		stackNames = append(stackNames, stackName)
		// fmt.Printf("=== %s %x\n", stackName, curStack)
	}
	// t := time.Unix(0, int64(ktime)).Format(time.StampNano)
	// pid := tpid >> 32
	// tid := uint32(tpid)
	// fmt.Printf("@@@ %d %s %s %x %x %d %d %d %d\n", flag, t, funcName, skb, ret, pid, tid, cpu, len(stacks))
	// return

	_, exist := AllEntry[skb]
	if !exist {
		AllEntry[skb] = make(TpidEntry)
	}
	e := Entry{
		Flag:       flag,
		Ktime:      ktime,
		Skb:        skb,
		Cpu:        cpu,
		TPid:       tpid,
		Addr:       addr,
		Ret:        ret,
		Depth:      len(stacks),
		StackRaw:   stacks,
		StackNames: stackNames,
		Name:       funcName,
	}
	AllEntry[skb][tpid+cpu] = append(AllEntry[skb][tpid+cpu], e)
	if flag == bpf.EXIT_FLAG && ret != 0 {
		_, exist = AllEntry[ret]
		if !exist {
			AllEntry[ret] = make(TpidEntry)
		}
		AllEntry[ret][tpid+cpu] = append(AllEntry[ret][tpid+cpu], e)

		// set ret value for fentry
		length := len(AllEntry[skb][tpid+cpu])
		for i := length - 1; i >= 0; i-- {
			v := AllEntry[skb][tpid+cpu][i]
			if v.Flag == bpf.ENTRY_FLAG && v.Name == e.Name {
				v.Ret = e.Ret
				if skb == 0 {
					AllEntry[skb][tpid+cpu] = append(AllEntry[skb][tpid+cpu][:i], AllEntry[skb][tpid+cpu][i+1:]...)
				}
				AllEntry[ret][tpid+cpu] = append(AllEntry[ret][tpid+cpu], v)
				break
			}
		}
	}
}

func IngestRecordv2(record *ringbuf.Record) {
	rd := KsymsParser

	addr := readRecord(record, bpf.OFFSET_IP)
	skb := readRecord(record, bpf.OFFSET_POSARG)
	funcName := rd.LookupByInstructionPointer(addr)
	// exist skb, join exist list
	if stack, found := GlobalMap[skb]; found {
		node := BuildStackNodeFromRecord(record)
		stack.CallStack = append(stack.CallStack, node)
	} else if funcName == "__alloc_skb" {
		ret := readRecord(record, bpf.OFFSET_RETARG)
		GlobalMap[ret] = SkbStack{
			Skb:       skb,
			CallStack: []SkbStackNode{BuildStackNodeFromRecord(record)},
		}
	}
}
