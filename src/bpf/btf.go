package bpf

import (
	"os"

	"github.com/cilium/ebpf/btf"
)

type SkbFunc struct {
	FuncName string
	ArgRet   int16
	ArgPos   int16
}

func GetSkbFuncList() (funcList []SkbFunc) {
	prefix := "/sys/kernel/btf/"
	entries, _ := os.ReadDir(prefix)
	kernelSpec, _ := btf.LoadKernelSpec()
	for _, e := range entries {
		f, _ := os.Open(prefix + e.Name())
		spec, err := btf.LoadSplitSpecFromReader(f, kernelSpec)
		if err != nil {
			panic(err)
		}
		iter := spec.Iterate()
		for iter.Next() {
			t := iter.Type
			argPos, argRet := getSkbPos(t)
			if argPos >= 0 || argRet >= 0 {
				funcList = append(funcList, SkbFunc{
					FuncName: t.TypeName(),
					ArgRet:   argRet,
					ArgPos:   argPos,
				})
			}
		}
	}
	return funcList
}

func getSkbPos(t btf.Type) (int16, int16) {
	argPos := -1
	argRet := -1
	switch v := t.(type) {
	case *btf.Func:
		proto := v.Type.(*btf.FuncProto)
		for pos, p := range proto.Params {
			switch paramType := p.Type.(type) {
			case *btf.Pointer:
				switch pointerType := paramType.Target.(type) {
				case *btf.Struct:
					if pointerType.Name == "sk_buff" {
						argPos = pos
						break
					}
				}
			}
		}
		switch v := proto.Return.(type) {
		case *btf.Pointer:
			switch t := v.Target.(type) {
			case *btf.Struct:
				if t.Name == "sk_buff" {
					argRet = len(proto.Params)
				}
			}

		}
	}
	return int16(argPos), int16(argRet)
}
