// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

package libbpf

import (
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	unix "golang.org/x/sys/unix"
)

import "C"

// KABPFProgType type
type KABPFProgType uint32

// KABPFProgType constants
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

// KABPFLinkType type
type KABPFLinkType uint32

// KABPFLinkType constants
const (
	KABPFLinkTypeUnspec KABPFLinkType = iota
	KABPFLinkTypeLSM
	KABPFLinkTypeKprobe
	KABPFLinkTypeKretprobe
	KABPFLinkTypeRawTracepoint
	KABPFLinkTypeTracepoint
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
	eventType KABPFLinkType

	bpfLink *libbpfgo.BPFLink
}

// KubeArmor RingBuffer wrapper structure
type KABPFRingBuffer struct {
	bpfMap *KABPFMap

	bpfRingBuffer *libbpfgo.RingBuffer
}

// KubeArmor PerfBuffer wrapper structure
type KABPFPerfBuffer struct {
	bpfMap *KABPFMap

	bpfPerfBuffer *libbpfgo.PerfBuffer
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

// Initialize ring buffer
func (o *KABPFObject) InitRingBuf(mapName string, eventsChan chan []byte) (*KABPFRingBuffer, error) {
	var err error
	var m *KABPFMap

	m, err = o.FindMapByName(mapName)
	if err != nil {
		return nil, err
	}

	var rb *libbpfgo.RingBuffer

	rb, err = o.bpfObj.InitRingBuf(m.Name(), eventsChan)
	if err != nil {
		return nil, err
	}

	return &KABPFRingBuffer{
		bpfMap:        m,
		bpfRingBuffer: rb,
	}, nil
}

// Initialize perf buffer
func (o *KABPFObject) InitPerfBuf(mapName string, eventsChan chan []byte, lostChan chan uint64, pageCnt int) (*KABPFPerfBuffer, error) {
	var err error
	var m *KABPFMap

	m, err = o.FindMapByName(mapName)
	if err != nil {
		return nil, err
	}

	var pb *libbpfgo.PerfBuffer

	pb, err = o.bpfObj.InitPerfBuf(m.Name(), eventsChan, lostChan, pageCnt)
	if err != nil {
		return nil, err
	}

	return &KABPFPerfBuffer{
		bpfMap:        m,
		bpfPerfBuffer: pb,
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

// Initialize ring buffer
func (m *KABPFMap) InitRingBuf(eventsChan chan []byte) (*KABPFRingBuffer, error) {
	return m.bpfObj.InitRingBuf(m.Name(), eventsChan)
}

// Initialize perf buffer
func (m *KABPFMap) InitPerfBuf(eventsChan chan []byte, lostChan chan uint64, pageCnt int) (*KABPFPerfBuffer, error) {
	return m.bpfObj.InitPerfBuf(m.Name(), eventsChan, lostChan, pageCnt)
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
		eventType: KABPFLinkTypeLSM,
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
		eventType: KABPFLinkTypeKprobe,
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
		eventType: KABPFLinkTypeKretprobe,
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
		eventType: KABPFLinkTypeRawTracepoint,
		bpfLink:   l,
	}, nil
}

// Attach Tracepoint
func (p *KABPFProgram) AttachTracepoint(category, eventName string) (*KABPFLink, error) {
	l, err := p.bpfProg.AttachTracepoint(category, eventName)
	if err != nil {
		return nil, err
	}

	return &KABPFLink{
		bpfProg:   p,
		eventName: eventName,
		eventType: KABPFLinkTypeTracepoint,
		bpfLink:   l,
	}, nil
}

// Get object pointer to which program belongs
func (p *KABPFProgram) Object() *KABPFObject {
	return p.bpfObj
}

// Get attached event name
func (l *KABPFLink) EventName() string {
	return l.eventName
}

// Get attached event type
func (l *KABPFLink) EventType() KABPFLinkType {
	return l.eventType
}

// Get program pointer to which link belongs
func (l *KABPFLink) Program() *KABPFProgram {
	return l.bpfProg
}

// Destroy link
func (l *KABPFLink) Destroy() error {
	return l.bpfLink.Destroy()
}

// Start to poll ring buffer
func (rb *KABPFRingBuffer) StartPoll() {
	rb.bpfRingBuffer.Start()
}

// Stop to poll ring buffer
func (rb *KABPFRingBuffer) StopPoll() {
	rb.bpfRingBuffer.Stop()
}

// Free ring buffer
func (rb *KABPFRingBuffer) Free() {
	rb.bpfRingBuffer.Close()
}

// Get map pointer to which ring buffer relates
func (rb *KABPFRingBuffer) Map() *KABPFMap {
	return rb.bpfMap
}

// Start to poll perf buffer
func (pb *KABPFPerfBuffer) StartPoll() {
	pb.bpfPerfBuffer.Start()
}

// Stop to poll perf buffer
func (pb *KABPFPerfBuffer) StopPoll() {
	pb.bpfPerfBuffer.Stop()
}

// Free perf buffer
func (pb *KABPFPerfBuffer) Free() {
	pb.bpfPerfBuffer.Close()
}

// Get map pointer to which perf buffer relates
func (pb *KABPFPerfBuffer) Map() *KABPFMap {
	return pb.bpfMap
}
