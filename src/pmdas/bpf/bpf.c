/*
 * BPF wrapper metric module.
 *
 * Copyright (c) 2021 Netflix, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <pcp/pmapi.h>
#include <pcp/pmda.h>
#include "domain.h"
#include "modules/module.h"
#include <sys/stat.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <dlfcn.h>
#include "bpf.h"

/* see libpcp.h __pmXx_int */
#define MAX_CLUSTER_ID ((1<<12) - 1)
#define MAX_INDOM_ID ((1<<22) - 1)

/* pmdaCacheOp cache IDs */
#define CACHE_CLUSTER_IDS 0
#define CACHE_INDOM_IDS 1

static int	isDSO = 1;		/* =0 I am a daemon */
static char	mypath[MAXPATHLEN];

/* metric and indom configuration will be dynamically filled in by modules */
static pmdaMetric * metrictab;
static pmdaIndom * indomtab;
static int metric_count = 0;
static int indom_count = 0;
static pmdaNameSpace *pmns;

/* command line option handling - both short and long options */
static pmLongOptions longopts[] = {
    PMDA_OPTIONS_HEADER("Options"),
    PMOPT_DEBUG,
    PMDAOPT_DOMAIN,
    PMDAOPT_LOGFILE,
    PMOPT_HELP,
    PMDA_OPTIONS_TEXT("\nExactly one of the following options may appear:"),
    PMDAOPT_INET,
    PMDAOPT_PIPE,
    PMDAOPT_UNIX,
    PMDAOPT_IPV6,
    PMDA_OPTIONS_END
};
static pmdaOptions opts = {
    .short_options = "D:d:i:l:pu:6:?",
    .long_options = longopts,
};

/*
 * callback provided to pmdaFetch
 */
static int
bpf_fetchCallBack(pmdaMetric *mdesc, unsigned int inst, pmAtomValue *atom)
{
    unsigned int	cluster = pmID_cluster(mdesc->m_desc.pmid);
    unsigned int	item = pmID_item(mdesc->m_desc.pmid);

    int cache_result;
    module* module;

    // only modules that have completed their init() successfully will be
    // available in modules_by_cluster
    cache_result = pmdaCacheLookup(CACHE_CLUSTER_IDS, cluster, NULL, (void**)&module);
    if (cache_result == PMDA_CACHE_ACTIVE) {
        return module->fetch_to_atom(item, inst, atom);
    }

    // To get here, must have had a valid entry in PMNS (so, a known cluster),
    // and yet no cluster id -> module map was found. Implication is that this
    // module exists but was not requested in configuration, so, 'no values' is
    // appropriate as the cluster is known but we have no values for it.
    return PMDA_FETCH_NOVALUES;
}

/**
 * wrapper for libbpf logging
 */
int bpf_printfn(enum libbpf_print_level level, const char *out, va_list ap)
{
    char logline[1024];
    vsprintf(logline, out, ap);
    size_t ln = strlen(logline) - 1;
    if (*logline && logline[ln] == '\n') 
        logline[ln] = '\0';

    int pmLevel;
    switch(level) {
        case LIBBPF_WARN:
            pmLevel = LOG_WARNING;
            break;
        case LIBBPF_INFO:
            pmLevel = LOG_INFO;
            break;
        case LIBBPF_DEBUG:
            pmLevel = LOG_DEBUG;
            break;
        default:
            pmLevel = LOG_ERR;
            break;
    }

    pmNotifyErr(pmLevel, "%s", logline);
    return 0;
}

/**
 * setrlimit required for BPF loading
 */
void bpf_setrlimit()
{
    struct rlimit rnew = {
        .rlim_cur = 100*1024*1024,
        .rlim_max = 100*1024*1024,
    };
    int ret = setrlimit(RLIMIT_MEMLOCK, &rnew);
    int err = errno;
    if (ret == 0) {
        pmNotifyErr(LOG_INFO, "setrlimit ok");
    } else {
        pmNotifyErr(LOG_ERR, "setrlimit failed: %d", err);
    }
}

/**
 * Load a single module from modules/
 *
 * This will call dlopen, look up the bpf_module to load the module.
 */
module* bpf_load_module(char * name)
{
    module *loaded_module = NULL;
    char *fullpath;
    char *error;

    int ret;
    ret = asprintf(&fullpath, "%s/bpf/modules/%s.so", pmGetConfig("PCP_PMDAS_DIR"), name);
    if (ret < 0) {
        pmNotifyErr(LOG_ERR, "could not construct log string?");
        return NULL;
    }

    pmNotifyErr(LOG_INFO, "loading: %s from %s", name, fullpath);

    void * dl_module = NULL;
    dl_module = dlopen(fullpath, RTLD_NOW);
    if (!dl_module) {
        error = dlerror();
        pmNotifyErr(LOG_INFO, "dlopen failed: %s, %s", fullpath, error);
        goto cleanup;
    }

    loaded_module = dlsym(dl_module, "bpf_module");
    if ((error = dlerror()) != NULL) {
        pmNotifyErr(LOG_ERR, "dlsym failed to find module: %s, %s", fullpath, error);
    }

cleanup:
    free(fullpath);
    return loaded_module;
}

/**
 * load all known modules
 */
void
bpf_load_modules(struct config cfg)
{
    int ret;
    char errorstring[1024];
    module *module;

    pmdaCacheResize(CACHE_CLUSTER_IDS, MAX_CLUSTER_ID);
    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_STRINGS);
    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_LOAD);
    pmdaCacheResize(CACHE_INDOM_IDS, MAX_INDOM_ID);
    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_STRINGS);
    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_LOAD);


    pmNotifyErr(LOG_INFO, "booting modules (%d)", cfg.module_count);

    for(int i = 0; i < cfg.module_count; i++) {
        if (cfg.module_names[i][0] == '#')
            continue;

        module = bpf_load_module(cfg.module_names[i]);
        if (module == NULL) {
            pmNotifyErr(LOG_ERR, "could not load module (%s)", cfg.module_names[i]);
            continue;
        }

        pmNotifyErr(LOG_INFO, "found: %s", cfg.module_names[i]);

        ret = module->init();
        if (ret != 0) {
            libbpf_strerror(ret, errorstring, 1023);
            pmNotifyErr(LOG_ERR, "module initialization failed: %d, %s", ret, errorstring);
            continue;
        }

        unsigned int cluster_id = pmdaCacheStore(CACHE_CLUSTER_IDS, PMDA_CACHE_ADD, cfg.module_names[i], module);
        pmNotifyErr(LOG_INFO, "module (%s) initialized with cluster_id = %d", cfg.module_names[i], cluster_id);
    }

    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_SAVE);
}

/**
 * register metrics for all known modules
 *
 * all modules will be registered to ensure PMNS matches
 */
void
bpf_register_module_metrics()
{
    // identify how much space we need and set up metric table area
    int total_metrics = 0;
    int total_indoms = 0;
    int cache_op_status;
    module* module;
    char indom[64];
    char *name;

    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_REWIND);
    cache_op_status = pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_NEXT);
    while(cache_op_status != -1) {
        int cluster_id = cache_op_status;
        cache_op_status = pmdaCacheLookup(CACHE_CLUSTER_IDS, cluster_id, NULL, (void**)&module);
        total_metrics += module->metric_count();
        total_indoms += module->indom_count();
        cache_op_status = pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_NEXT);
    }

    // set up indom mapping
    metrictab = (pmdaMetric*) calloc(total_metrics, sizeof(pmdaMetric));
    indomtab = (pmdaIndom*) calloc(total_indoms, sizeof(pmdaIndom));

    // each module needs to set up its tables, starting at the next available slot
    int current_metric = 0;
    int current_indom = 0;
    pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_REWIND);
    cache_op_status = pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_NEXT);
    while(cache_op_status != -1) {
        int cluster_id = cache_op_status;
        cache_op_status = pmdaCacheLookup(CACHE_CLUSTER_IDS, cluster_id, &name, (void**)&module);

        // set up indom mapping for the module
        for(int i = 0; i < module->indom_count(); i++) {
            pmsprintf(indom, sizeof(indom), "%s/%d", name, i);
            int serial = pmdaCacheStore(CACHE_INDOM_IDS, PMDA_CACHE_ADD, indom, NULL);
            module->set_indom_serial(i, serial);
        }

        // register all of the metrics
        module->register_metrics(cluster_id, &metrictab[current_metric], &indomtab[current_indom]);

        // progress
        current_metric += module->metric_count();
        current_indom += module->indom_count();
        cache_op_status = pmdaCacheOp(CACHE_CLUSTER_IDS, PMDA_CACHE_WALK_NEXT);
    }

    metric_count = current_metric;
    indom_count = current_indom;
}

/**
 * Fetch callback for pre-refresh
 */
int
bpf_fetch(int numpmid, pmID pmidlist[], pmResult **resp, pmdaExt *pmda)
{
    module* target;
    int cache_result;

    for(int i = 0; i < numpmid; i++) {
        unsigned int cluster_id = pmID_cluster(pmidlist[i]);
        unsigned int item = pmID_item(pmidlist[i]);
        cache_result = pmdaCacheLookup(CACHE_CLUSTER_IDS, cluster_id, NULL, (void**)&target);
        if (cache_result == PMDA_CACHE_ACTIVE) {
            target->refresh(item);
        }
    }

    return pmdaFetch(numpmid, pmidlist, resp, pmda);
}

void
bpf_setup_pmns()
{
    int ret;
    char name[64];
    module* target;

    ret = pmdaTreeCreate(&pmns);
    if (ret < 0)
    {
        pmNotifyErr(LOG_ERR, "%s: failed to create new pmns: %s\n", pmGetProgname(), pmErrStr(ret));
        pmns = NULL;
        return;
    }

    for (int i = 0; i < metric_count; i++) {
        unsigned int cluster_id = pmID_cluster(metrictab[i].m_desc.pmid);
        unsigned int item = pmID_item(metrictab[i].m_desc.pmid);

        ret = pmdaCacheLookup(CACHE_CLUSTER_IDS, cluster_id, NULL, (void**)&target);
        if (ret == PMDA_CACHE_ACTIVE) {
            pmsprintf(name, sizeof(name), "bpf.%s", target->metric_name(item));
            pmdaTreeInsert(pmns, metrictab[i].m_desc.pmid, name);
        }
    }

    pmdaTreeRebuildHash(pmns, metric_count);
}

/**
 * Load configuration from file
 */
struct config
bpf_load_config(char* filename)
{
    // cheap and nasty; do two passes on the file
    FILE *config_file;
    char line[256];
    unsigned int module_num;
    char * found_line;

    struct config config;
    config.module_count = 0;

    config_file = fopen(filename, "r");
    while (!feof(config_file)) {
        found_line = fgets(line, sizeof(line), config_file);
        if (found_line == NULL)
            continue;

        if (line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = '\0';
        }

        pmNotifyErr(LOG_DEBUG, "config line = %s", line);

        if (strlen(line) > 0) {
            config.module_count++;
        }
    }

    config.module_names = (char**) calloc(config.module_count, sizeof(char*));

    fseek(config_file, 0, SEEK_SET);
    module_num = 0;
    while (!feof(config_file)) {
        found_line = fgets(line, sizeof(line), config_file);
        if (found_line == NULL)
            continue;

        if (line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = '\0';
        }
        if (strlen(line) > 0) {
            config.module_names[module_num] = strdup(line);
            module_num++;
        }
    }

    return config;
}

/**
 * Callbacks to support dynamic namespace
 */

static int
bpf_pmid(const char *name, pmID *pmid, pmdaExt *pmda)
{
	return pmdaTreePMID(pmns, name, pmid);
}

static int
bpf_name(pmID pmid, char ***nameset, pmdaExt *pmda)
{
	return pmdaTreeName(pmns, pmid, nameset);
}

static int
bpf_children(const char *name, int flag, char ***kids, int **sts, pmdaExt *pmda)
{
	return pmdaTreeChildren(pmns, name, flag, kids, sts);
}

/*
 * Initialise the agent (both daemon and DSO).
 */
void 
bpf_init(pmdaInterface *dp)
{
    if (isDSO) {
        int sep = pmPathSeparator();
        pmsprintf(mypath, sizeof(mypath), "%s%c" "bpf" "%c" "help",
            pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
        pmdaDSO(dp, PMDA_INTERFACE_7, "bpf", mypath);
    }

    if (dp->status != 0)
        return;

    // TODO module configuration
    char* config_filename;
    int ret = asprintf(&config_filename, "%s/bpf/bpf.conf", pmGetConfig("PCP_PMDAS_DIR"));
    if (ret <= 0) {
        pmNotifyErr(LOG_ERR, "could not construct config filename");
    } else {
        pmNotifyErr(LOG_INFO, "loading configuration: %s", config_filename);
    }
    struct config config = bpf_load_config(config_filename);
    pmNotifyErr(LOG_INFO, "loaded configuration: %s", config_filename);
    free(config_filename);

    // libbpf setup
    bpf_setrlimit();
    libbpf_set_print(bpf_printfn);

    bpf_load_modules(config);
    bpf_register_module_metrics();

    // set up PMDA callbacks
    pmdaSetFetchCallBack(dp, bpf_fetchCallBack);
    dp->version.any.fetch = bpf_fetch;
	dp->version.four.pmid = bpf_pmid;
	dp->version.four.name = bpf_name;
	dp->version.four.children = bpf_children;

    pmdaInit(dp, indomtab, indom_count, metrictab, metric_count);

    bpf_setup_pmns();
}

/*
 * Set up the agent if running as a daemon.
 */
int
main(int argc, char **argv)
{
    int sep = pmPathSeparator();
    pmdaInterface dispatch;

    isDSO = 0;
    pmSetProgname(argv[0]);

    pmsprintf(mypath, sizeof(mypath), "%s%c" "bpf" "%c" "help",
        pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
    pmdaDaemon(&dispatch, PMDA_INTERFACE_7, pmGetProgname(), BPF,
        "bpf.log", mypath);

    pmdaGetOptions(argc, argv, &opts, &dispatch);
    if (opts.errors) {
        pmdaUsageMessage(&opts);
        exit(1);
    }

    pmdaOpenLog(&dispatch);
    pmdaConnect(&dispatch);
    bpf_init(&dispatch);
    pmdaMain(&dispatch);

    exit(0);
}
