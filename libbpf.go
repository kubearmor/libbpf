// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

package libbpf

import (
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	unix "golang.org/x/sys/unix"
)

import "C"

type KABPFProgType uint32

const (
	KABPFProgTypeUnspec                KABPFProgType = unix.BPF_PROG_TYPE_UNSPEC
	KABPFProgTypeSocketFilter          KABPFProgType = unix.BPF_PROG_TYPE_SOCKET_FILTER
	KABPFProgTypeKprobe                KABPFProgType = unix.BPF_PROG_TYPE_KPROBE
	KABPFProgTypeSchedCls              KABPFProgType = unix.BPF_PROG_TYPE_SCHED_CLS
	KABPFProgTypeSchedAct              KABPFProgType = unix.BPF_PROG_TYPE_SCHED_ACT
	KABPFProgTypeTracepoint            KABPFProgType = unix.BPF_PROG_TYPE_TRACEPOINT
	KABPFProgTypeXDP                   KABPFProgType = unix.BPF_PROG_TYPE_XDP
	KABPFProgTypePerfEvent             KABPFProgType = unix.BPF_PROG_TYPE_PERF_EVENT
	KABPFProgTypeCgroupSKB             KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_SKB
	KABPFProgTypeCgroupSock            KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_SOCK
	KABPFProgTypeLwtIn                 KABPFProgType = unix.BPF_PROG_TYPE_LWT_IN
	KABPFProgTypeLwtOut                KABPFProgType = unix.BPF_PROG_TYPE_LWT_OUT
	KABPFProgTypeLwtXmit               KABPFProgType = unix.BPF_PROG_TYPE_LWT_XMIT
	KABPFProgTypeSockOps               KABPFProgType = unix.BPF_PROG_TYPE_SOCK_OPS
	KABPFProgTypeSkSKB                 KABPFProgType = unix.BPF_PROG_TYPE_SK_SKB
	KABPFProgTypeCgroupDevice          KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_DEVICE
	KABPFProgTypeSkMsg                 KABPFProgType = unix.BPF_PROG_TYPE_SK_MSG
	KABPFProgTypeRawTracepoint         KABPFProgType = unix.BPF_PROG_TYPE_RAW_TRACEPOINT
	KABPFProgTypeCgroupSockAddr        KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	KABPFProgTypeLwtSeg6Local          KABPFProgType = unix.BPF_PROG_TYPE_LWT_SEG6LOCAL
	KABPFProgTypeLircMode2             KABPFProgType = unix.BPF_PROG_TYPE_LIRC_MODE2
	KABPFProgTypeSkReuseport           KABPFProgType = unix.BPF_PROG_TYPE_SK_REUSEPORT
	KABPFProgTypeFlowDissector         KABPFProgType = unix.BPF_PROG_TYPE_FLOW_DISSECTOR
	KABPFProgTypeCgroupSysctl          KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_SYSCTL
	KABPFProgTypeRawTracepointWritable KABPFProgType = unix.BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	KABPFProgTypeCgroupSockopt         KABPFProgType = unix.BPF_PROG_TYPE_CGROUP_SOCKOPT
	KABPFProgTypeTracing               KABPFProgType = unix.BPF_PROG_TYPE_TRACING
	KABPFProgTypeStructOps             KABPFProgType = unix.BPF_PROG_TYPE_STRUCT_OPS
	KABPFProgTypeExt                   KABPFProgType = unix.BPF_PROG_TYPE_EXT
	KABPFProgTypeLSM                   KABPFProgType = unix.BPF_PROG_TYPE_LSM
	KABPFProgTypeSkLookup              KABPFProgType = unix.BPF_PROG_TYPE_SK_LOOKUP
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

// KubeArmor BPFMap Element interface
type KABPFMapElement interface {
	KeyPointer() unsafe.Pointer
	ValuePointer() unsafe.Pointer
	MapName() string

	SetFoundValue(value []byte)
}

// KubeArmor BPFProgram wrapper structure
type KABPFProgram struct {
	bpfObj *KABPFObject

	bpfProg *libbpfgo.BPFProg
}

// KubeArmor BPFLink wrapper structure
type KABPFLink struct {
	bpfProg   *KABPFProgram
	eventName string

	bpfLink *libbpfgo.BPFLink
}

// Open object file
func OpenObjectFromFile(bpfObjFile string) (*KABPFObject, error) {
	mod, err := libbpfgo.NewModuleFromFile(bpfObjFile)
	if err != nil {
		return nil, err
	}

	return &KABPFObject{
		bpfObj: mod,
	}, nil
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
	if err != nil {
		return nil, err
	}

	return &KABPFMap{
		bpfObj: o,
		bpfMap: m,
	}, nil
}

// Get program from object
func (o *KABPFObject) FindProgramByName(progName string) (*KABPFProgram, error) {
	p, err := o.bpfObj.GetProgram(progName)
	if err != nil {
		return nil, err
	}

	return &KABPFProgram{
		bpfObj:  o,
		bpfProg: p,
	}, nil
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
// The elem will have its value updated
func (m *KABPFMap) LookupElement(elem KABPFMapElement) ([]byte, error) {
	val, err := m.bpfMap.GetValue(elem.KeyPointer())
	if err != nil {
		return nil, err
	}

	elem.SetFoundValue(val)

	return val, err
}

// Update map element
func (m *KABPFMap) UpdateElement(elem KABPFMapElement) error {
	return m.bpfMap.Update(elem.KeyPointer(), elem.ValuePointer())
}

// Delete map element
func (m *KABPFMap) DeleteElement(elem KABPFMapElement) error {
	return m.bpfMap.DeleteKey(elem.KeyPointer())
}

// Get object pointer to which map belongs
func (m *KABPFMap) Object() *KABPFObject {
	return m.bpfObj
}

// Get program fd
func (p *KABPFProgram) FD() int {
	return p.bpfProg.GetFd()
}

// Get program name
func (p *KABPFProgram) Name() string {
	return p.bpfProg.GetName()
}

// Get program type
func (p *KABPFProgram) GetType() KABPFProgType {
	return KABPFProgType(p.bpfProg.GetType())
}

// Attach LSM
func (p *KABPFProgram) AttachLSM() (*KABPFLink, error) {
	l, err := p.bpfProg.AttachLSM()
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: "",
		bpfLink:   l,
	}, nil
}

// Attach Kprobe
// This should be used for kernels > 4.17
func (p *KABPFProgram) AttachKprobe(eventName string) (*KABPFLink, error) {
	l, err := p.bpfProg.AttachKprobe(eventName)
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: eventName,
		bpfLink:   l,
	}, nil
}

// Attach Kretprobe
// This should be used for kernels > 4.17
func (p *KABPFProgram) AttachKretprobe(eventName string) (*KABPFLink, error) {
	l, err := p.bpfProg.AttachKretprobe(eventName)
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: eventName,
		bpfLink:   l,
	}, nil
}

// Attach Raw Tracepoint
func (p *KABPFProgram) AttachRawTracepoint(eventName string) (*KABPFLink, error) {
	l, err := p.bpfProg.AttachRawTracepoint(eventName)
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: eventName,
		bpfLink:   l,
	}, nil
}

// Attach Tracepoint
func (p *KABPFProgram) AttachTracepoint(eventName string) (*KABPFLink, error) {
	l, err := p.bpfProg.AttachTracepoint(eventName)
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: eventName,
		bpfLink:   l,
	}, nil
}

// Get object pointer to which program belongs
func (p *KABPFProgram) Object() *KABPFObject {
	return p.bpfObj
}

// Get attached function name
func (l *KABPFLink) EventName() string {
	return l.eventName
}

// Get program pointer to which link belongs
func (l *KABPFLink) Program() *KABPFProgram {
	return l.bpfProg
}

// Detach link
func (l *KABPFLink) Detach() error {
	return nil
}
