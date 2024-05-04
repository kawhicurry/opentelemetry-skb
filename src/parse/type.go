package parse

import (
	"syscall"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
)

type Entry struct {
	Name       string
	Flag       uint64
	Ktime      uint64
	Skb        uint64
	Timestamp  uint64
	Cpu        uint64
	TPid       uint64
	Addr       uint64
	Ret        uint64
	Depth      int
	StackRaw   []uint64
	StackNames []string
}

type SkbEntry map[uint64]TpidEntry
type TpidEntry map[uint64][]Entry

var KsymsParser *kallsyms.KAllSyms
var AllEntry SkbEntry
var BootTime time.Time

func init() {
	var err error
	KsymsParser, err = kallsyms.NewKAllSyms()
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

type SkbStack struct {
	Skb       uint64
	CallStack []SkbStackNode
}

type SkbStackNode struct {
	Name string
	TPid uint64

	Flag       uint64
	Ktime      uint64
	Skb        uint64
	Addr       uint64
	Ret        uint64
	StackNames []string
	CallStack  []SkbStackNode
}

type SkbMap map[uint64]SkbStack

var GlobalMap SkbMap
