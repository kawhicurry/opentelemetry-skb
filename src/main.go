package main

import (
	"fmt"
	"opentelemetry-skb/bpf"
	"opentelemetry-skb/parse"

	"github.com/cilium/ebpf/rlimit"
	"github.com/schollz/progressbar/v3"
)

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}
	funcList := []bpf.SkbFunc{
		{FuncName: "ip_rcv", ArgPos: 0, ArgRet: -1},
		// {FuncName: "skb_put", ArgPos: 0, ArgRet: 1},
		{FuncName: "icmp_rcv", ArgPos: 0, ArgRet: -1},
		{FuncName: "ip_rcv_finish", ArgPos: 2, ArgRet: -1},
	}
	funcList = bpf.GetSkbFuncList()
	rb, err := bpf.InitRingbuf()
	if err != nil {
		panic(err)
	}
	defer rb.Close()
	success, failed := 0, 0
	loadBar := progressbar.Default(int64(len(funcList)), "loading:")
	for _, f := range funcList {
		loader, err := bpf.LoadTracingProg(f, rb.GetFD())
		if err != nil {
			// fmt.Println(i, f, err)
			failed++
		} else {
			success++
		}
		loadBar.Add(1)
		defer loader.Close()
	}
	fmt.Println(failed, success, len(funcList))
	// const maxIngestSize = 1000
	const maxIngestSize = 500000
	readBar := progressbar.Default(maxIngestSize, "profiling")
	for i := 0; i < maxIngestSize; i++ {
		record, err := rb.Read()
		if err != nil {
			panic(err)
		}
		parse.IngestRecord(&record)
		readBar.Add(1)
	}
	parse.ParseAllEntry()
	fmt.Println("finish")
}
