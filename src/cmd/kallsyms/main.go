package main

import "opentelemetry-skb/kallsyms"

func main() {
	k, _ := kallsyms.NewKAllSyms()
	k.SymbolExists("ip_rcv")
}
