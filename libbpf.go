// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

package libbpf

import (
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
)

// KubeArmor BPFObject wrapper structure
type KABPFObject struct {
	bpfObj *libbpfgo.Module
}

// KubeArmor BPFMap wrapper structure
type KABPFMap struct {
	bpfObj *KABPFObject
	bpfMap *libbpfgo.BPFMap
}

// Open object file
func OpenObjectFromFile(bpfObjFile string) (*KABPFObject, error) {
	mod, err := libbpfgo.NewModuleFromFile(bpfObjFile)

	return &KABPFObject{
		bpfObj: mod,
	}, err
}

// Load object
func (o *KABPFObject) Load() error {
	return o.bpfObj.BPFLoadObject()
}

// Close object
func (o *KABPFObject) Close() {
	o.bpfObj.Close()
}

// Get map from object
func (o *KABPFObject) FindMapByName(mapName string) (*KABPFMap, error) {
	m, err := o.bpfObj.GetMap(mapName)

	return &KABPFMap{
		bpfObj: o,
		bpfMap: m,
	}, err
}

// Get map fd
func (m *KABPFMap) FD() int {
	return m.bpfMap.GetFd()
}

// Get map name
func (m *KABPFMap) Name() string {
	return m.bpfMap.GetName()
}

// Get map max entries
func (m *KABPFMap) MaxEntries() uint32 {
	return m.bpfMap.GetMaxEntries()
}

// Set map max entries
func (m *KABPFMap) SetMaxEntries(maxEntries uint32) error {
	return m.bpfMap.Resize(maxEntries)
}

// Check if map is pinned
func (m *KABPFMap) IsPinned() bool {
	return m.bpfMap.IsPinned()
}

// Get map pin path
func (m *KABPFMap) PinPath() string {
	return m.bpfMap.GetPinPath()
}

// Set map pin path
func (m *KABPFMap) SetPinPath(pinPath string) error {
	return m.bpfMap.SetPinPath(pinPath)
}

// Pin map
func (m *KABPFMap) Pin(pinPath string) error {
	return m.bpfMap.Pin(pinPath)
}

// Unpin map
func (m *KABPFMap) Unpin(pinPath string) error {
	return m.bpfMap.Unpin(pinPath)
}

// Get map key size
func (m *KABPFMap) KeySize() int {
	return m.bpfMap.KeySize()
}

// Get map value size
func (m *KABPFMap) ValueSize() int {
	return m.bpfMap.ValueSize()
}

// Lookup map element
func (m *KABPFMap) LookupElement(key unsafe.Pointer) ([]byte, error) {
	return m.bpfMap.GetValue(key)
}

// Update map element
func (m *KABPFMap) UpdateElement(key, value unsafe.Pointer) error {
	return m.bpfMap.Update(key, value)
}

// Delete map element
func (m *KABPFMap) DeleteElement(key unsafe.Pointer) error {
	return m.bpfMap.DeleteKey(key)
}

// Get object pointer to which map belongs
func (m *KABPFMap) Object() *KABPFObject {
	return m.bpfObj
}
