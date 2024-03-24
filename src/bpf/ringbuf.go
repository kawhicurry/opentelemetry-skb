package bpf

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

//	func (b *MapLoader) Read() (ringbuf.Record, error) {
//		return b.reader.Read()
//	}
func InitRingbuf() (RingbufLoader, error) {
	b := RingbufLoader{}
	err := b.initRingbuf()
	if err != nil {
		return RingbufLoader{}, nil
	}
	return b, err
}

func (l *RingbufLoader) initRingbuf() (err error) {
	l.ringbuf, l.reader, err = loadMap()
	return err
}
func loadMap() (rb *ebpf.Map, rd *ringbuf.Reader, err error) {
	rb, err = ebpf.NewMap(&ebpf.MapSpec{
		Name:       "eventRingbuf",
		Type:       ebpf.RingBuf,
		MaxEntries: 16 * 1024 * uint32(os.Getpagesize()),
	})
	if err != nil {
		return nil, nil, err
	}
	rd, err = ringbuf.NewReader(rb)
	if err != nil {
		return nil, nil, err
	}
	return rb, rd, err
}

func (l *RingbufLoader) GetFD() int {
	return l.ringbuf.FD()
}

func (l *RingbufLoader) Read() (ringbuf.Record, error) {
	return l.reader.Read()
}
func (l *RingbufLoader) BufferSize() int {
	return l.reader.BufferSize()
}

func (l *RingbufLoader) Close() {
	closeList := []Closer{
		l.reader,
		l.ringbuf,
	}
	for _, c := range closeList {
		if c != nil {
			c.Close()
		}
	}
}
