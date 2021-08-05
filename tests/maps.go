// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

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
	fmt.Println("Map Name:       ", m.Name())
	fmt.Println("Map FD:         ", m.FD())
	fmt.Println("Map Pinned:     ", m.IsPinned())
	fmt.Println("Map Pin Path:   ", m.PinPath())
	fmt.Println("Map Key Size:   ", m.KeySize())
	fmt.Println("Map Value Size: ", m.ValueSize())
	fmt.Println("Map Max Entries:", m.MaxEntries())
}

func main() {
	var err error
	var bpfObj *lbpf.KABPFObject
	var bpfMap1, bpfMap2 *lbpf.KABPFMap

	bpfObj, err = lbpf.OpenObjectFromFile("maps.bpf.o")
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
}
