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

// Test map element management
func testMapElementManagement(m *lbpf.KABPFMap) {
	var err error
	var key uint32 = 0
	var value1 uint32 = 1337
	var value2 []byte

	fmt.Println()
	fmt.Println("Testing element management methods: started")

	err = m.UpdateElement(unsafe.Pointer(&key), unsafe.Pointer(&value1))
	exitIfError(err)

	value2, err = m.LookupElement(unsafe.Pointer(&key))
	exitIfError(err)
	if binary.LittleEndian.Uint32(value2) != value1 {
		exitIfError(errors.New("value1 is not equal to value2"))
	}

	err = m.DeleteElement(unsafe.Pointer(&key))
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

	testMapElementManagement(bpfMap1)
}
