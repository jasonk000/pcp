/**
 * Common imports and helpers for BPF module that will be loaded by the kernel.
 */

/* next imports require this defined so they are configured to run in kernel */
#define __KERNEL__

/* represents all of the kernel structs; generated via bpftool */
#include "vmlinux_cut.h"

/* bpf kernel-side */
#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

/* create new element or update existing */
#define BPF_ANY       0

/* log2 helpers so for histograms */
static inline
unsigned int bpf_log2(unsigned int v)
{
    unsigned int r;
    unsigned int shift;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}

static inline
unsigned int bpf_log2l(unsigned long v)
{
  unsigned int hi = v >> 32;
  if (hi)
    return bpf_log2(hi) + 32 + 1;
  else
    return bpf_log2(v) + 1;
}

/**
 * Create an entry in a BPF map. If the entry already exists, add the value.
 */
static inline void add_or_create_entry(void *map, const void *key, const unsigned long val) {
    unsigned long *value = bpf_map_lookup_elem(map, key);
    if (value != 0)
    {
	    // equivalent to a LOCK XADD to the existing entry
        ((void)__sync_fetch_and_add(value, val));
    }
    else
    {
        // does not exist yet, create it
        bpf_map_update_elem(map, key, &val, BPF_ANY);
    }
}

/* kernel version compatibility; this is required for earlier kernels but ignored in later libbpf */
__u32 _version SEC("version") = 1;
