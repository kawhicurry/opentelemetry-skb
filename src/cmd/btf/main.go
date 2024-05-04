package main

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

func main() {
	// k, err := kallsyms.NewKAllSyms()
	// if err != nil {
	// 	panic(err)
	// }
	// if k.SymbolExists("netvsc_alloc_recv_skb") {
	// 	fmt.Println("Exist")
	// } else {
	// 	fmt.Println("None")
	// }
	// name := k.LookupByInstructionPointer(0xffffffff97f6ceec)
	// fmt.Println(name)
	v := GetSkbType()
	fmt.Println(v)
}

// func GetSkbFuncList() {
// 	prefix := "/sys/kernel/btf/"
// 	entries, _ := os.ReadDir(prefix)
// 	kernelSpec, _ := btf.LoadKernelSpec()
// 	for _, e := range entries {
// 		f, _ := os.Open(prefix + e.Name())
// 		spec, err := btf.LoadSplitSpecFromReader(f, kernelSpec)
// 		if err != nil {
// 			panic(err)
// 		}
// 		iter := spec.Iterate()
// 		for iter.Next() {
// 			t := iter.Type
// 			args := getSkbPos(t)
// 			if len(args) > 1 {
// 				fmt.Println(t.TypeName(), args)
// 			}
// 		}
// 	}
// }

// func getSkbPos(t btf.Type) []int {
// 	args := []int{}
// 	switch v := t.(type) {
// 	case *btf.Func:
// 		proto := v.Type.(*btf.FuncProto)
// 		for pos, p := range proto.Params {
// 			switch paramType := p.Type.(type) {
// 			case *btf.Pointer:
// 				switch pointerType := paramType.Target.(type) {
// 				case *btf.Struct:
// 					if pointerType.Name == "sk_buff" {
// 						args = append(args, pos)
// 					}
// 				}
// 			}
// 		}
// 	}
// 	return args
// }

func GetSkbType() uint32 {
	spec, _ := btf.LoadKernelSpec()
	iter := spec.Iterate()
	for iter.Next() {
		t := iter.Type
		if t.TypeName() == "sk_buff" {
			switch st := t.(type) {
			case *btf.Struct:
				for _, m := range st.Members {
					switch sst := m.Type.(type) {
					case *btf.Union:
						for _, mm := range sst.Members {
							// skb_mstamp_ns shared the same offset
							if mm.Name == "tstamp" {
								return uint32(m.Offset)
							}
						}
					}
				}
			}
		}
	}
	return 0
}
