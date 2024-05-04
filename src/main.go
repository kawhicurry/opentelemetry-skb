package main

import (
	"fmt"
	"opentelemetry-skb/bpf"
	"opentelemetry-skb/parse"

	"github.com/cilium/ebpf/rlimit"
	"github.com/schollz/progressbar/v3"
)

const (
// maxIngestSize = 5000
// maxIngestSize = 500000
)

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}
	debug := false
	// debug = true
	maxIngestSize := 500000
	funcList := bpf.GetSkbFuncList()
	if debug {
		maxIngestSize = 50
		funcList = []bpf.SkbFunc{
			{FuncName: "ip_rcv", ArgPos: 0, ArgRet: -1},
			// {FuncName: "__alloc_skb", ArgPos: -1, ArgRet: 1},
			// {FuncName: "netvsc_alloc_recv_skb", ArgPos: -1, ArgRet: 1},
			// {FuncName: "skb_put", ArgPos: 0, ArgRet: -1},
			// {FuncName: "icmp_rcv", ArgPos: 0, ArgRet: -1},
			// {FuncName: "ip_rcv_finish", ArgPos: 2, ArgRet: -1},
		}
	}
	rb, err := bpf.InitRingbuf()
	if err != nil {
		panic(err)
	}
	defer rb.Close()
	success, failed := 0, 0
	fmt.Println("Will load num:", len(funcList))
	loadBar := progressbar.Default(int64(len(funcList)), "Loading: ")
	for _, sf := range funcList {
		loadBar.Add(1)
		loader, err := bpf.LoadTracingProg(sf, rb.GetFD())
		if err != nil {
			fmt.Println("Load failed:", sf.FuncName, sf.ArgPos, sf.ArgRet, err)
			failed++
		} else {
			fmt.Println("Load success:", sf.FuncName, sf.ArgPos, sf.ArgRet)
			success++
		}
		defer loader.Close()
	}
	ingestBar := progressbar.Default(int64(maxIngestSize), "Ingesting")
	for i := 0; i < maxIngestSize; i++ {
		ingestBar.Add(1)
		record, err := rb.Read()
		if err != nil {
			panic(err)
		}
		// fmt.Println("Reamain:", record.Remaining, rb.BufferSize(), i, maxIngestSize)
		parse.IngestRecord(&record)
	}
	parse.ParseAllEntry()
	fmt.Println("finish")
}
