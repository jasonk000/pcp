#include "module.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pcp/pmda.h>

#include "module_helpers.h"

#define NUM_LATENCY_SLOTS 63
pmdaInstid biolatency_instances[NUM_LATENCY_SLOTS];

int biolatency_fd = -1;

char * biolatency_name()
{
    return "biolatency";
}

int biolatency_metric_count()
{
    return 1;
}

int biolatency_indom_count()
{
    return 1;
}

int biolatency_cluster()
{
    return BIOLATENCY_CLUSTER;
}

void biolatency_register(pmdaMetric *metrics, pmdaIndom *indoms)
{
    // must match PMNS

	/* bpf.disk.all.latency */
    metrics[0] = (struct pmdaMetric)
        { /* m_user */ NULL,
            { /* m_desc */
                PMDA_PMID(BIOLATENCY_CLUSTER, 0),
                PM_TYPE_U64,
                BIOLATENCY_INDOM,
                PM_SEM_COUNTER,
                PMDA_PMUNITS(0, 1, 0, 0, PM_TIME_USEC, 0)
            }
        };

    indoms[0] = (struct pmdaIndom)
        {
            BIOLATENCY_INDOM,
            sizeof(biolatency_instances)/sizeof(pmdaIndom),
            biolatency_instances
        };
}

int biolatency_init()
{
    struct bpf_object *bpf_obj;
    char errorstring[1024];
    struct bpf_program *bpfprg;
    const char *name;
    int ret;
    char *bpf_path;

    ret = asprintf(&bpf_path, "%s/bpf/modules/biolatency.bpf.o", pmGetConfig("PCP_PMDAS_DIR"));
    if (ret <= 0) {
        pmNotifyErr(LOG_ERR, "could not construct bpf module path");
        return ret;
    }

    bpf_obj = bpf_object__open(bpf_path);
    free(bpf_path);
    name = bpf_object__name(bpf_obj);
    pmNotifyErr(LOG_INFO, "booting: %s", name);

    ret = bpf_object__load(bpf_obj);
    if (ret == 0) {
        pmNotifyErr(LOG_INFO, "bpf loaded");
    } else {
        libbpf_strerror(ret, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf load failed: %d, %s", ret, errorstring);
        return ret;
    }

    pmNotifyErr(LOG_INFO, "attaching bpf programs");
    bpfprg = bpf_program__next(NULL, bpf_obj);
    while (bpfprg != NULL)
    {
        bpf_program__attach(bpfprg);
        bpfprg = bpf_program__next(bpfprg, bpf_obj);
    }
    pmNotifyErr(LOG_INFO, "attached!");

    biolatency_fd = bpf_object__find_map_fd_by_name(bpf_obj, "latencies");
    if (biolatency_fd >= 0) {
        pmNotifyErr(LOG_INFO, "opened latencies map, fd: %d", biolatency_fd);
    } else {
        libbpf_strerror(biolatency_fd, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf map open failed: %d, %s", biolatency_fd, errorstring);
        return biolatency_fd;
    }

    fill_instids_log2(NUM_LATENCY_SLOTS, biolatency_instances);

    return 0;
}

int biolatency_shutdown()
{
    if (biolatency_fd != 0) {
        close(biolatency_fd);
        biolatency_fd = -1;
    }
    return 0;
}

void biolatency_refresh(unsigned int item)
{
    /* do nothing */
}

int biolatency_fetch_to_atom(unsigned int item, unsigned int inst, pmAtomValue *atom)
{
    if (inst == PM_IN_NULL) {
        return PM_ERR_INST;
    }

    if (biolatency_fd == -1) {
        // not initialised
        return PMDA_FETCH_NOVALUES;
    }

    unsigned long key = inst;
    unsigned long value = 0;
    int ret = bpf_map_lookup_elem(biolatency_fd, &key, &value);
    if (ret == -1) {
        return PMDA_FETCH_NOVALUES;
    }

    atom->ull = value;
    return PMDA_FETCH_STATIC;
}

module* load_module()
{
    module *new_module = malloc(sizeof(module));
    new_module->module_name = biolatency_name;
    new_module->init = biolatency_init;
    new_module->register_metrics = biolatency_register;
    new_module->cluster = biolatency_cluster;
    new_module->metric_count = biolatency_metric_count;
    new_module->indom_count = biolatency_indom_count;
    new_module->shutdown = biolatency_shutdown;
    new_module->refresh = biolatency_refresh;
    new_module->fetch_to_atom = biolatency_fetch_to_atom;
    return new_module;
}
