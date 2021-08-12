// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	lbpf "github.com/kubearmor/libbpf"
)

// These fields can be private using getters and setters
// Just to make this example straightforward, they are public
type PinnedMapElem struct {
	Key   uint32
	Value uint32
}

// Method to satisfy KABPFMapElement interface
func (pme *PinnedMapElem) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Key)
}

// Method to satisfy KABPFMapElement interface
func (pme *PinnedMapElem) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Value)
}

// Method to satisfy KABPFMapElement interface
func (pme *PinnedMapElem) SetFoundValue(value []byte) {
	pme.Value = binary.LittleEndian.Uint32(value)
}

// Method to satisfy KABPFMapElement interface
func (pme *PinnedMapElem) MapName() string {
	return "pinned_map"
}

// Exit if err is not nil
// Don't use this in production
func exitIfError(err error) {
	if err != nil {
		fmt.Printf("\n%v\n", err)
		os.Exit(-1)
	}
}

// Print map information
func printMapInfo(m *lbpf.KABPFMap) {
	fmt.Println()
	fmt.Println("Map Object:     ", unsafe.Pointer(m.Object()))
	fmt.Println("Map Name:       ", m.Name())
	fmt.Println("Map FD:         ", m.FD())
	fmt.Println("Map Pinned:     ", m.IsPinned())
	fmt.Println("Map Pin Path:   ", m.PinPath())
	fmt.Println("Map Key Size:   ", m.KeySize())
	fmt.Println("Map Value Size: ", m.ValueSize())
	fmt.Println("Map Max Entries:", m.MaxEntries())
}

// Print map element information
func printMapElemInfo(me lbpf.KABPFMapElement) {
	fmt.Println()
	fmt.Println("Map Name:         ", me.MapName())
	fmt.Println("Map Key Pointer:  ", me.KeyPointer())
	fmt.Println("Map Value Pointer:", me.ValuePointer())
	fmt.Println()
}

// Test map element management
func testPinnedMapElementManagement(m *lbpf.KABPFMap) {
	var err error
	var pme PinnedMapElem
	var retValue []byte

	fmt.Println()
	fmt.Println("Testing element management methods: started")

	printMapElemInfo(&pme)

	pme.Key = 0
	pme.Value = 1337
	err = m.UpdateElement(&pme)
	exitIfError(err)

	pme.Value = 0
	// retValue could be dropped since pme.Value will be updated after this call
	retValue, err = m.LookupElement(&pme)
	exitIfError(err)

	if pme.Value != 1337 {
		exitIfError(errors.New("pme.Value is not equal to 1337"))
	}

	if uint32(binary.LittleEndian.Uint32(retValue)) != pme.Value {
		exitIfError(errors.New("retValue is not equal to 1337"))
	}

	err = m.DeleteElement(&pme)
	exitIfError(err)

	fmt.Println("Testing element management methods: all good")
}

func main() {
	var err error
	var bpfObj *lbpf.KABPFObject
	var bpfMap1, bpfMap2 *lbpf.KABPFMap

	bpfObj, err = lbpf.OpenObjectFromFile("./maps.bpf.o")
	exitIfError(err)
	defer bpfObj.Close()

	err = bpfObj.Load()
	exitIfError(err)

	bpfMap1, err = bpfObj.FindMapByName("pinned_map")
	exitIfError(err)
	defer bpfMap1.Unpin(bpfMap1.PinPath())

	printMapInfo(bpfMap1)

	bpfMap2, err = bpfObj.FindMapByName("unpinned_map")
	exitIfError(err)

	printMapInfo(bpfMap2)

	testPinnedMapElementManagement(bpfMap1)
}
