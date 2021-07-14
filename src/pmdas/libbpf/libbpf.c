/*
 * Simple, configurable PMDA
 *
 * Copyright (c) 2012-2014,2017 Red Hat.
 * Copyright (c) 1995,2004 Silicon Graphics, Inc.  All Rights Reserved.
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

/*
 * All metrics supported in this PMDA - one table entry for each.
 * The 4th field specifies the serial number of the instance domain
 * for the metric, and must be either PM_INDOM_NULL (denoting a
 * metric that only ever has a single value), or the serial number
 * of one of the instance domains declared in the instance domain table
 * (i.e. in indomtab, above).
 */

pmdaMetric * metrictab;
pmdaIndom * indomtab;

static int	isDSO = 1;		/* =0 I am a daemon */
static char	*username;

static int metric_count = 0;
static int indom_count = 0;

static char	mypath[MAXPATHLEN];

static module** modules;
static int module_count;

/* command line option handling - both short and long options */
static pmLongOptions longopts[] = {
    PMDA_OPTIONS_HEADER("Options"),
    PMOPT_DEBUG,
    PMDAOPT_DOMAIN,
    PMDAOPT_LOGFILE,
    PMDAOPT_USERNAME,
    PMOPT_HELP,
    PMDA_OPTIONS_TEXT("\nExactly one of the following options may appear:"),
    PMDAOPT_INET,
    PMDAOPT_PIPE,
    PMDAOPT_UNIX,
    PMDAOPT_IPV6,
    PMDA_OPTIONS_END
};
static pmdaOptions opts = {
    .short_options = "D:d:i:l:pu:U:6:?",
    .long_options = longopts,
};

/*
 * callback provided to pmdaFetch
 */
static int
libbpf_fetchCallBack(pmdaMetric *mdesc, unsigned int inst, pmAtomValue *atom)
{
    unsigned int	cluster = pmID_cluster(mdesc->m_desc.pmid);
    unsigned int	item = pmID_item(mdesc->m_desc.pmid);

    for (int i = 0; i < module_count; i++) {
        if (modules[i]->cluster() == cluster) {
            return modules[cluster]->fetch_to_atom(item, inst, atom);        
        }
    }
 
    // A module should have picked up the cluster, based on pmns, even
    // if it responded with PMDA_FETCH_NOVALUES indicating no values available
    // for the metric. So, if we have made it here, we've been passed a cluster
    // that we do not know how to handle. Could be a pmns vs module config issue.
    return PM_ERR_PMID;
}

int libbpf_printfn(enum libbpf_print_level level, const char *out, va_list ap)
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

void libbpf_setrlimit()
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

module* libbpf_load_module(char * name)
{
    module *loaded_module = NULL;
    module *(*load_module_fn)();
    char *fullpath;
    char *error;

    int ret;
    ret = asprintf(&fullpath, "/var/lib/pcp/pmdas/libbpf/modules/%s.so", name);
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

    load_module_fn = dlsym(dl_module, "load_module");
    if ((error = dlerror()) != NULL) {
        pmNotifyErr(LOG_ERR, "dlsym failed: %s, %s", fullpath, error);
    } else {
        loaded_module = (*load_module_fn)();
    }

cleanup:
    free(fullpath);
    return loaded_module;
}

void
libbpf_load_modules()
{
    module_count = sizeof(all_modules)/sizeof(all_modules[0]);
    modules = (module**) malloc(2 * sizeof(module*));
    for(int i = 0; i < module_count; i++) {
        modules[i] = libbpf_load_module(all_modules[i]);
    }
}

void
libbpf_register_modules()
{
    // identify how much space we need and set up metric table area
    int total_metrics = 0;
    int total_indoms = 0;
    for(int i = 0; i < module_count; i++) {
        total_metrics += modules[i]->metric_count();
        total_indoms += modules[i]->indom_count();
    }
    metrictab = (pmdaMetric*) malloc(total_metrics * sizeof(pmdaMetric));
    indomtab = (pmdaIndom*) malloc(total_indoms * sizeof(pmdaIndom));

    // each module needs to set up its tables, starting at the next available slot
    int current_metric = 0;
    int current_indom = 0;
    for(int i = 0; i < module_count; i++) {
        pmNotifyErr(LOG_INFO, "registering: %s", modules[i]->module_name());
        modules[i]->register_metrics(&metrictab[current_metric], &indomtab[current_indom]);

        current_metric += modules[i]->metric_count();
        current_indom += modules[i]->indom_count();
    }

    metric_count = current_metric;
    indom_count = current_indom;
}

void
libbpf_init_modules(unsigned int module_names_count, char** module_names)
{
    int ret;
    char errorstring[1024];

    for(int i = 0; i < module_count; i++) {
        bool found = false;
        char *name = modules[i]->module_name();

        for(int j = 0; j < module_names_count; j++) {
            if (strcmp(name, module_names[j]) == 0) {
                found = true;
            }
        }

        if (!found)
            continue;

        pmNotifyErr(LOG_INFO, "booting: %s", modules[i]->module_name());
        ret = modules[i]->init();
        if (ret != 0) {
            libbpf_strerror(ret, errorstring, 1023);
            pmNotifyErr(LOG_ERR, "module initialization failed: %d, %s", ret, errorstring);
            modules[i] = NULL;
            continue;
        }

        pmNotifyErr(LOG_INFO, "module initialized");
    }
}

int
libbpf_fetch(int numpmid, pmID pmidlist[], pmResult **resp, pmdaExt *pmda)
{
    for(int i = 0; i < numpmid; i++) {
        unsigned int cluster = pmID_cluster(pmidlist[i]);
        unsigned int item = pmID_item(pmidlist[i]);
        if (cluster >= 0 && cluster < module_count && modules[cluster] != NULL) {
            modules[cluster]->refresh(item);
        }
    }

    return pmdaFetch(numpmid, pmidlist, resp, pmda);
}

/*
 * Initialise the agent (both daemon and DSO).
 */
void 
libbpf_init(pmdaInterface *dp)
{
    if (isDSO) {
        int sep = pmPathSeparator();
        pmsprintf(mypath, sizeof(mypath), "%s%c" "libbpf" "%c" "help",
            pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
        pmdaDSO(dp, PMDA_INTERFACE_7, "libbpf", mypath);
    }

    if (dp->status != 0)
        return;

    libbpf_setrlimit();
    libbpf_set_print(libbpf_printfn);

    libbpf_load_modules();
    libbpf_register_modules();

    // TODO module configuration
    libbpf_init_modules(sizeof(modules_to_load)/sizeof(modules_to_load[0]), modules_to_load);

    pmdaSetFetchCallBack(dp, libbpf_fetchCallBack);
    dp->version.any.fetch = libbpf_fetch;

    pmdaInit(dp, indomtab, indom_count, metrictab, metric_count);
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
    pmGetUsername(&username);

    pmsprintf(mypath, sizeof(mypath), "%s%c" "libbpf" "%c" "help", pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
    pmdaDaemon(&dispatch, PMDA_INTERFACE_7, pmGetProgname(), LIBBPF, "libbpf.log", mypath);

    pmdaGetOptions(argc, argv, &opts, &dispatch);
    if (opts.errors) {
        pmdaUsageMessage(&opts);
        exit(1);
    }
    if (opts.username)
        username = opts.username;

    pmdaOpenLog(&dispatch);
    pmdaConnect(&dispatch);
    libbpf_init(&dispatch);
    pmdaMain(&dispatch);

    exit(0);
}
