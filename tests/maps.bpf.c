// Copyright 2021 Authors of kubearmor/libbpf
// SPDX-License-Identifier: Apache-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
    __uint(max_entries, 1 << 13);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pinned_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
    __uint(max_entries, 1 << 12);
} unpinned_map SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";
