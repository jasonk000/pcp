#include "common.h"

// Copyright 2016 Netflix, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

// relicensing w/ GPL to use GPL helpers (BPF_CORE_READ); Netflix
char _license[] SEC("license") = "GPL";

#define MAX_TASK_ENTRIES	10240
#define MAX_LATENCY_ENTRIES 64
#define TASK_RUNNING 	0

SEC("maps")
struct bpf_map_def enqueued = {
	.type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_TASK_ENTRIES,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
};

SEC("maps")
struct bpf_map_def latencies = {
	.type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_LATENCY_ENTRIES,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
};

// record enqueue timestamp
static inline int trace_enqueue(int pid)
{
    if (pid == 0) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&enqueued, &pid, &ts, 0);
    return 0;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(wake_up_new_task, struct task_struct *p)
{
    int pid = BPF_CORE_READ(p, pid);
    return trace_enqueue(pid);
}

SEC("kprobe/ttwu_do_wakeup")
int BPF_KPROBE(ttwu_do_wakeup, struct rq *rq, struct task_struct *p, int wake_flags)
{
    int pid = BPF_CORE_READ(p, pid);
    return trace_enqueue(pid);
}

// calculate latency
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
    u32 pid, tgid;
    u64 ts, *tsp, delta, slot;

    // ivcsw: treat like an enqueue event and store timestamp
    if (BPF_CORE_READ(prev, state) == TASK_RUNNING) {
        tgid = BPF_CORE_READ(prev, tgid);
        pid = BPF_CORE_READ(prev, pid);
        if (pid != 0) {
            trace_enqueue(pid);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    if (pid == 0)
        return 0;

    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem(&enqueued, &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }

    delta = bpf_ktime_get_ns() - *tsp;
    if (delta < 0) {
        return 0;
    }

    // store delta in histogram
    slot = bpf_log2l(delta);
    add_or_create_entry(&latencies, &slot, 1);

    bpf_map_delete_elem(&enqueued, &pid);
    return 0;
}
