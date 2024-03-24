package parse

import (
	"context"
	"fmt"
	"opentelemetry-skb/bpf"
	"sort"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func ParseAllEntry() {
	shutdown := initTracer()
	defer shutdown()

	for skb, tpidEntry := range AllEntry {
		parseSkbMap(context.Background(), skb, tpidEntry)
	}
}

func GetPlantEntry() {
	plantList := []Entry{}
	for skb, skbEntry := range AllEntry {
		if skb == 0 {
			fmt.Println("Not consumed:", len(skbEntry))
			continue
		}
		for _, tpidEntry := range skbEntry {
			plantList = append(plantList, tpidEntry...)
		}
	}
	sort.Slice(plantList, func(i int, j int) bool {
		return plantList[i].Ktime < plantList[j].Ktime
	})
	for _, v := range plantList {
		t := time.Unix(0, int64(v.Ktime)).Format(time.StampNano)
		pid := v.TPid >> 32
		tid := uint32(v.TPid)
		// fmt.Printf("@@@ %s %d %s %s %x %x %d %d %d %d\n", strings.Repeat(" ", len(v.StackRaw)-min+1), v.Flag, t, v.Name, v.Skb, v.Ret, pid, tid, v.Cpu, len(v.StackRaw))
		fmt.Printf("@@@ %d %s %s %x %x %d %d %d %d\n", v.Flag, t, v.Name, v.Skb, v.Ret, pid, tid, v.Cpu, len(v.StackRaw))
	}
}

func parseSkbMap(ctx context.Context, skb uint64, tpidEntry TpidEntry) {
	if len(tpidEntry) == 0 {
		return
	}
	startTime := ^uint64(0)
	endTime := uint64(0)
	for _, list := range tpidEntry {
		sort.Slice(list, func(i, j int) bool {
			return list[i].Ktime < list[j].Ktime
		})
		if list[0].Ktime < startTime {
			startTime = list[0].Ktime
		}
		if list[len(list)-1].Ktime > endTime {
			endTime = list[len(list)-1].Ktime
		}
	}

	// ctx, span := Tracer.Start(ctx, "skb", trace.WithAttributes(attribute.Int64("skb", int64(skb))))
	// defer span.End()
	kstartTime := BootTime.Add(time.Duration(startTime))
	kendTime := BootTime.Add(time.Duration(endTime))
	newCtx, span := Tracer.Start(ctx, "skb", trace.WithTimestamp(kstartTime))
	defer span.End(trace.WithTimestamp(kendTime))

	for _, list := range tpidEntry {
		parseTpidMap(newCtx, list)
	}
}

func parseTpidMap(ctx context.Context, list []Entry) {
	// ctx, span := Tracer.Start(ctx, "tpid")
	// defer span.End()
	kstartTime := BootTime.Add(time.Duration(list[0].Ktime))
	kendTime := BootTime.Add(time.Duration(list[len(list)-1].Ktime))
	newCtx, span := Tracer.Start(ctx, "tpid", trace.WithTimestamp(kstartTime))
	defer span.End(trace.WithTimestamp(kendTime))

	for i := 0; i < len(list); i += 1 {
		i = parseEntry(newCtx, i, list)
	}
}

// call recursive
func parseEntry(ctx context.Context, index int, list []Entry) int {
	curEntry := list[index]
	// situation that list start with fexit
	if curEntry.Flag == bpf.EXIT_FLAG {
		return index
	}
	// situation that list end with fentry
	if index+1 == len(list) {
		return index
	}
	kstartTime := BootTime.Add(time.Duration(curEntry.Ktime))
	kendTime := BootTime.Add(time.Duration(list[index].Ktime))
	newCtx, span := Tracer.Start(ctx, curEntry.Name, trace.WithTimestamp(kstartTime), trace.WithAttributes(
		// newCtx, span := Tracer.Start(ctx, curEntry.Name, trace.WithAttributes(
		attribute.String("name", curEntry.Name),
		attribute.Int("flag", int(curEntry.Flag)),
		attribute.String("skb", fmt.Sprint(curEntry.Skb)),
		attribute.Int("cpu", int(curEntry.Cpu)),
		attribute.String("tpid", fmt.Sprint(curEntry.TPid)),
		attribute.String("begin", fmt.Sprint(curEntry.Ktime)),
		attribute.Int("depth", curEntry.Depth),
		attribute.StringSlice("stacks", curEntry.StackNames),
	))
	// defer span.End()
	defer span.End(trace.WithTimestamp(kendTime))
	index++
	nextEntry := list[index]
	if nextEntry.Flag == bpf.ENTRY_FLAG {
		index = parseEntry(newCtx, index, list)
	}
	exitEntry := list[index]

	retVal := ""
	if exitEntry.Name == curEntry.Name {
		retVal = fmt.Sprint(exitEntry.Ret)
	}
	span.SetAttributes(
		attribute.String("end", fmt.Sprint(exitEntry.Ktime)),
		attribute.String("ret", retVal),
	)
	return index
}
