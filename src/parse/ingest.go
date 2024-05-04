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
	timestamp := readRecord(record, bpf.OFFSET_TIMESTAMP)
	tpid := readRecord(record, bpf.OFFSET_TPID)
	cpu := readRecord(record, bpf.OFFSET_CPU)
	addr := readRecord(record, bpf.OFFSET_IP)
	skb := readRecord(record, bpf.OFFSET_POSARG)
	ret := readRecord(record, bpf.OFFSET_RETARG)
	stacks := []uint64{}
	stackNames := []string{}
	funcName := rd.LookupByInstructionPointer(addr)
	skip := true
	length := int16(len(record.RawSample))
	for i := bpf.OFFSET_STACKTRACE; i <= length; i += 8 {
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

	e := Entry{
		Flag:       flag,
		Ktime:      ktime,
		Skb:        skb,
		Timestamp:  timestamp,
		Cpu:        cpu,
		TPid:       tpid,
		Addr:       addr,
		Ret:        ret,
		Depth:      len(stacks),
		StackRaw:   stacks,
		StackNames: stackNames,
		Name:       funcName,
	}

	_, exist := AllEntry[skb]
	if !exist {
		AllEntry[skb] = make(TpidEntry)
	}
	key := tpid + cpu
	AllEntry[skb][key] = append(AllEntry[skb][key], e)
	if flag == bpf.EXIT_FLAG && ret != 0 {
		_, exist = AllEntry[ret]
		if !exist {
			AllEntry[ret] = make(TpidEntry)
		}
		AllEntry[ret][key] = append(AllEntry[ret][key], e)

		// set ret value for fentry
		length := len(AllEntry[skb][key])
		for i := length - 1; i >= 0; i-- {
			v := AllEntry[skb][key][i]
			if v.Flag == bpf.ENTRY_FLAG && v.Name == e.Name {
				v.Ret = e.Ret
				if skb == 0 {
					AllEntry[skb][key] = append(AllEntry[skb][key][:i], AllEntry[skb][key][i+1:]...)
				}
				AllEntry[ret][key] = append(AllEntry[ret][key], v)
				break
			}
		}
	}
}

func IngestRecordv2(record *ringbuf.Record) {
	// rd := KsymsParser

	// addr := readRecord(record, bpf.OFFSET_IP)
	skb := readRecord(record, bpf.OFFSET_POSARG)
	ret := readRecord(record, bpf.OFFSET_RETARG)
	// funcName := rd.LookupByInstructionPointer(addr)
	// exist skb, join exist list
	if stack, found := GlobalMap[skb]; found {
		node := BuildStackNodeFromRecord(record)
		stack.CallStack = append(stack.CallStack, node)
	} else {
		GlobalMap[ret] = SkbStack{
			Skb:       skb,
			CallStack: []SkbStackNode{BuildStackNodeFromRecord(record)},
		}
	}
}
