package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func LoadTracingProg(f SkbFunc, ringbufFD int) (ProgLoader, error) {
	loader := ProgLoader{}
	err := loader.loadTracingProg(f, ringbufFD)
	if err != nil {
		loader.Close()
	}
	return loader, err
}

func (l *ProgLoader) loadTracingProg(f SkbFunc, fd int) error {
	insn := GetInsn(fd, f.ArgPos, f.ArgRet, ENTRY_FLAG)
	prog, link, err := loadProg(f.FuncName, ebpf.AttachTraceFEntry, insn)
	if err != nil {
		return err
	}
	l.entryProg = prog
	l.entryLink = link
	insn = GetInsn(fd, f.ArgPos, f.ArgRet, EXIT_FLAG)
	prog, link, err = loadProg(f.FuncName, ebpf.AttachTraceFExit, insn)
	if err != nil {
		return err
	}
	l.exitProg = prog
	l.exitLink = link
	return nil
}

func loadProg(name string, attachType ebpf.AttachType, instructions asm.Instructions) (*ebpf.Program, link.Link, error) {
	// instrucions := GetInsn(b.eventMap.FD(), b.argPos, b.argRet)
	prog, err := ebpf.NewProgram(
		&ebpf.ProgramSpec{
			Name:         name,
			Type:         ebpf.Tracing,
			AttachType:   attachType,
			AttachTo:     name,
			License:      "GPL",
			Instructions: instructions,
		})
	if err != nil {
		return nil, nil, err
	}
	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	return prog, link, err
}
func (l *ProgLoader) Close() {
	closeList := []Closer{
		l.entryLink,
		l.entryProg,
		l.exitLink,
		l.exitProg,
	}
	for _, c := range closeList {
		if c != nil {
			c.Close()
		}
	}
}
