package parse

import (
	"context"
	"opentelemetry-skb/bpf"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Entry struct {
	Name       string
	Flag       uint64
	Ktime      uint64
	Skb        uint64
	TPid       uint64
	Addr       uint64
	Ret        uint64
	Depth      int
	StackRaw   []uint64
	StackNames []string
}

type TpidEntry map[uint64][]Entry
type SkbEntry map[uint64]TpidEntry

var RD *kallsyms.KAllSyms
var AllEntry SkbEntry
var BootTime time.Time

func init() {
	var err error
	RD, err = kallsyms.NewKAllSyms()
	if err != nil {
		panic(err)
	}
	AllEntry = make(SkbEntry)

	var info syscall.Sysinfo_t
	err = syscall.Sysinfo(&info)
	if err != nil {
		panic(err)
	}
	BootTime = time.Now().Add(-time.Duration(info.Uptime) * time.Second)
}

func readRecord(rc *ringbuf.Record, offset int16) uint64 {
	return bpf.ByteOrder().Uint64(rc.RawSample[offset : offset+8])
}

func IngestRecord(record *ringbuf.Record) {
	rd := RD

	flag := readRecord(record, bpf.OFFSET_FLAG)
	ktime := readRecord(record, bpf.OFFSET_KTIME)
	pid := readRecord(record, bpf.OFFSET_TPID)
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
	}

	_, exist := AllEntry[skb]
	if !exist {
		AllEntry[skb] = make(TpidEntry)
	}
	e := Entry{
		Flag:       flag,
		Ktime:      ktime,
		Skb:        skb,
		TPid:       pid,
		Addr:       addr,
		Ret:        ret,
		Depth:      len(stacks),
		StackRaw:   stacks,
		StackNames: stackNames,
		Name:       funcName,
	}
	AllEntry[skb][pid] = append(AllEntry[skb][pid], e)
	if ret != 0 {
		_, exist = AllEntry[ret]
		if !exist {
			AllEntry[ret] = make(TpidEntry)
		}
		AllEntry[ret][pid] = append(AllEntry[ret][pid], e)
	}
}

func ParseAllEntry() {
	shutdown := initTracer()
	defer shutdown()

	for _, tpidEntry := range AllEntry {
		parseSkbMap(tpidEntry)

	}
}

func parseSkbMap(tpidEntry TpidEntry) {
	ctx := context.Background()
	defer ctx.Done()

	startTime := ^uint64(0)
	endTime := uint64(0)
	for _, list := range tpidEntry {
		if list[0].Ktime < startTime {
			startTime = list[0].Ktime
		}
		if list[len(list)-1].Ktime > endTime {
			endTime = list[len(list)-1].Ktime
		}
	}

	kstartTime := BootTime.Add(time.Duration(startTime))
	kendTime := BootTime.Add(time.Duration(endTime))
	ctx, span := Tracer.Start(ctx, "skb", trace.WithTimestamp(kstartTime))
	defer span.End(trace.WithTimestamp(kendTime))

	for _, list := range tpidEntry {
		parseTpidMap(ctx, list)
	}
}

func parseTpidMap(ctx context.Context, list []Entry) {
	// sort.Slice(list, func(i, j int) bool {
	// 	return list[i].Ktime < list[j].Ktime
	// })

	kstartTime := BootTime.Add(time.Duration(list[0].Ktime))
	kendTime := BootTime.Add(time.Duration(list[len(list)-1].Ktime))
	ctx, span := Tracer.Start(ctx, "tpid", trace.WithTimestamp(kstartTime))
	defer span.End(trace.WithTimestamp(kendTime))

	for i := 0; i < len(list); i += 1 {
		i = parseEntry2(ctx, i, list)
	}
}

// call recursive
func parseEntry2(ctx context.Context, index int, list []Entry) int {
	curEntry := list[index]
	if curEntry.Flag == bpf.EXIT_FLAG {
		return index
	}
	kstartTime := BootTime.Add(time.Duration(curEntry.Ktime))
	newCtx, span := Tracer.Start(ctx, curEntry.Name, trace.WithTimestamp(kstartTime))
	defer func() {
		kendTime := BootTime.Add(time.Duration(list[index].Ktime))
		span.End(trace.WithTimestamp(kendTime))
	}()
	span.SetAttributes(
		attribute.String("name", curEntry.Name),
		attribute.Int("skb", int(curEntry.Skb)),
		attribute.Int("tpid", int(curEntry.TPid)),
		attribute.Int("ktime", int(curEntry.Ktime)),
		attribute.Int("depth", curEntry.Depth),
		attribute.StringSlice("stacks", curEntry.StackNames),
	)
	if index+1 == len(list) {
		return index
	}
	nextEntry := list[index+1]
	if nextEntry.Depth == curEntry.Depth {
		if nextEntry.Flag == bpf.EXIT_FLAG {
			index = parseEntry2(newCtx, index+1, list)
			return index
		}
		return index
	} else if nextEntry.Depth > curEntry.Depth {
		// will be called at defer
		index = parseEntry2(newCtx, index+1, list)
		return index
	}
	return index
}
