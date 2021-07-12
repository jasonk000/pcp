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
#include <sys/stat.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <math.h>

/*
 * list of instances
 */

#define NUM_LATENCY_SLOTS 64
static pmdaInstid latency[NUM_LATENCY_SLOTS];

/*
 * instance domains
 */

#define LATENCY_INDOM 0
static pmdaIndom indomtab[] = {
    { LATENCY_INDOM, sizeof(latency)/sizeof(latency[0]), latency }
};

/*
 * All metrics supported in this PMDA - one table entry for each.
 * The 4th field specifies the serial number of the instance domain
 * for the metric, and must be either PM_INDOM_NULL (denoting a
 * metric that only ever has a single value), or the serial number
 * of one of the instance domains declared in the instance domain table
 * (i.e. in indomtab, above).
 */

static pmdaMetric metrictab[] = {
    { /* m_user */ NULL,
        { /* m_desc */
            PMDA_PMID(0, 0),
            PM_TYPE_U64,
            LATENCY_INDOM,
            PM_SEM_COUNTER,
            PMDA_PMUNITS(0, 1, 0, 0, PM_TIME_NSEC, 0)
        }
    },
    { /* m_user */ NULL,
        { /* m_desc */
            PMDA_PMID(1, 1),
            PM_TYPE_U64,
            LATENCY_INDOM,
            PM_SEM_COUNTER,
            PMDA_PMUNITS(0, 1, 0, 0, PM_TIME_NSEC, 0)
        }
    }
};

static int	isDSO = 1;		/* =0 I am a daemon */
static char	*username;

static int runqlat_fd = 0;
static int biolatency_fd = 0;

static char	mypath[MAXPATHLEN];

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

    if (inst == PM_IN_NULL)
        return PM_ERR_INST;

    if (cluster == 0 && item == 0) {
        unsigned long map_key = inst;
        unsigned long value = 0;
        int ret = bpf_map_lookup_elem(runqlat_fd, &map_key, &value);
        if (ret == -1) {
            return PMDA_FETCH_NOVALUES;
        }
        atom->ull = value;
    } else if (cluster == 1 && item == 1) {
        unsigned long map_key = inst;
        unsigned long value = 0;
        int ret = bpf_map_lookup_elem(biolatency_fd, &map_key, &value);
        if (ret == -1) {
            return PMDA_FETCH_NOVALUES;
        }
        atom->ull = value;
    } else {
        return PM_ERR_PMID;
    }

    return PMDA_FETCH_STATIC;
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

void
libbpf_bootbpf()
{
    struct bpf_object *bpf_obj;
    const char *name;
    int ret;
    char errorstring[1024];
    struct bpf_program *bpfprg;

    libbpf_setrlimit();
    libbpf_set_print(libbpf_printfn);

    // runqlat

    bpf_obj = bpf_object__open("/var/lib/pcp/pmdas/libbpf/modules/runqlat.o");
    name = bpf_object__name(bpf_obj);
    pmNotifyErr(LOG_INFO, "booting: %s", name);

    bpfprg = bpf_program__next(NULL, bpf_obj);
    while (bpfprg != NULL)
    {
        bpf_program__set_type(bpfprg, BPF_PROG_TYPE_KPROBE);
        bpf_program__set_expected_attach_type(bpfprg, MAX_BPF_ATTACH_TYPE);
        bpfprg = bpf_program__next(bpfprg, bpf_obj);
    }

    ret = bpf_object__load(bpf_obj);
    if (ret == 0) {
        pmNotifyErr(LOG_INFO, "bpf loaded");
    } else {
        libbpf_strerror(ret, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf load failed: %d, %s", ret, errorstring);
        return;
    }

    runqlat_fd = bpf_object__find_map_fd_by_name(bpf_obj, "latencies");
    if (runqlat_fd >= 0) {
        pmNotifyErr(LOG_INFO, "opened latencies map, fd: %d", runqlat_fd);
    } else {
        libbpf_strerror(ret, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf map open failed: %d, %s", ret, errorstring);
        return;
    }

    pmNotifyErr(LOG_INFO, "attaching bpf programs");
    bpfprg = bpf_program__next(NULL, bpf_obj);
    while (bpfprg != NULL)
    {
        bpf_program__attach(bpfprg);
        bpfprg = bpf_program__next(bpfprg, bpf_obj);
    }
    pmNotifyErr(LOG_INFO, "attached!");

    // biolatency

    bpf_obj = bpf_object__open("/var/lib/pcp/pmdas/libbpf/modules/biolatency.o");
    name = bpf_object__name(bpf_obj);
    pmNotifyErr(LOG_INFO, "booting: %s", name);

    bpfprg = bpf_program__next(NULL, bpf_obj);
    while (bpfprg != NULL)
    {
        bpf_program__set_type(bpfprg, BPF_PROG_TYPE_KPROBE);
        bpf_program__set_expected_attach_type(bpfprg, MAX_BPF_ATTACH_TYPE);
        bpfprg = bpf_program__next(bpfprg, bpf_obj);
    }

    ret = bpf_object__load(bpf_obj);
    if (ret == 0) {
        pmNotifyErr(LOG_INFO, "bpf loaded");
    } else {
        libbpf_strerror(ret, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf load failed: %d, %s", ret, errorstring);
        return;
    }

    biolatency_fd = bpf_object__find_map_fd_by_name(bpf_obj, "latencies");
    if (biolatency_fd >= 0) {
        pmNotifyErr(LOG_INFO, "opened latencies map, fd: %d", biolatency_fd);
    } else {
        libbpf_strerror(ret, errorstring, 1023);
        pmNotifyErr(LOG_ERR, "bpf map open failed: %d, %s", ret, errorstring);
        return;
    }

    pmNotifyErr(LOG_INFO, "attaching bpf programs");
    bpfprg = bpf_program__next(NULL, bpf_obj);
    while (bpfprg != NULL)
    {
        bpf_program__attach(bpfprg);
        bpfprg = bpf_program__next(bpfprg, bpf_obj);
    }
    pmNotifyErr(LOG_INFO, "attached!");
}

/*
 * Initialise the agent (both daemon and DSO).
 */
void 
libbpf_init(pmdaInterface *dp)
{
    if (isDSO) {
        int sep = pmPathSeparator();
        pmsprintf(mypath, sizeof(mypath), "%s%c" "simple" "%c" "help",
            pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
        pmdaDSO(dp, PMDA_INTERFACE_7, "simple DSO", mypath);
    }

    if (dp->status != 0)
        return;

    libbpf_bootbpf();

    pmdaSetFetchCallBack(dp, libbpf_fetchCallBack);

    pmdaInit(dp, indomtab, sizeof(indomtab)/sizeof(indomtab[0]), metrictab,
         sizeof(metrictab)/sizeof(metrictab[0]));
}

void fill_metadata()
{
    for(int i = 0; i < NUM_LATENCY_SLOTS; i++) {
        char *string;
        int lower = round(pow(2, i));
        int upper = round(pow(2, i+1));
        int ret = asprintf(&string, "%d-%d", lower, upper);
        if (ret > 0) {
            latency[i].i_inst = i;
            latency[i].i_name = string;
        }
    }
}

/*
 * Set up the agent if running as a daemon.
 */
int
main(int argc, char **argv)
{
    fill_metadata();

    int			sep = pmPathSeparator();
    pmdaInterface	dispatch;

    isDSO = 0;
    pmSetProgname(argv[0]);
    pmGetUsername(&username);

    pmsprintf(mypath, sizeof(mypath), "%s%c" "libbpf" "%c" "help",
        pmGetConfig("PCP_PMDAS_DIR"), sep, sep);
    pmdaDaemon(&dispatch, PMDA_INTERFACE_7, pmGetProgname(), LIBBPF,
        "libbpf.log", mypath);

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
