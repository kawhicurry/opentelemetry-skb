package main

import (
	"fmt"
	"opentelemetry-skb/kallsyms"
)

func main() {
	k, err := kallsyms.NewKAllSyms()
	if err != nil {
		panic(err)
	}
	if k.SymbolExists("netvsc_alloc_recv_skb") {
		fmt.Println("Exist")
	} else {
		fmt.Println("None")
	}
	name := k.LookupByInstructionPointer(0xffffffff97f6ceec)
	fmt.Println(name)
}
