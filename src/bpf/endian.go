package bpf

import (
	"encoding/binary"
	"unsafe"
)

const intWidth int = int(unsafe.Sizeof(0))

var byteOrder binary.ByteOrder

// ByteOrder returns the byte order for the CPU's native endianness.
func ByteOrder() binary.ByteOrder { return byteOrder }
func init() {
	i := int(0x1)
	if v := (*[intWidth]byte)(unsafe.Pointer(&i)); v[0] == 0 {
		byteOrder = binary.BigEndian
	} else {
		byteOrder = binary.LittleEndian
	}
}
