#include "common.h"

// Copyright (c) 2015 Brendan Gregg.
// Licensed under the Apache License, Version 2.0 (the "License")
char _license[] SEC("license") = "Apache-2.0";

#define MAX_IO_START_ENTRIES	10240
#define MAX_LATENCY_ENTRIES 512

SEC("maps")
struct bpf_map_def request_starts = {
	.type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_IO_START_ENTRIES,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(u64),
};

SEC("maps")
struct bpf_map_def latencies = {
	.type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_LATENCY_ENTRIES,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
};

int record_block_start(struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_starts, &req, &ts, 0);
    return 0;
}

SEC("kprobe/blk_start_request")
int BPF_KPROBE(blk_start_request, struct request *req)
{
    return record_block_start(req);
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(blk_mq_start_request, struct request *req)
{
    return record_block_start(req);
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(blk_account_io_done, struct request *req)
{
    u64 *tsp, delta, slot;

    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem(&request_starts, &req);
    if (tsp == 0) {
        return 0;   // missed issue
    }

    delta = bpf_ktime_get_ns() - *tsp;
    if (delta < 0) {
        return 0;
    }
    delta /= 1000;  // convert ns to usec

    // store as histogram
    slot = bpf_log2l(delta / 1000);
    add_or_create_entry(&latencies, &slot, 1);

    bpf_map_delete_elem(&request_starts, &req);
    return 0;
}
