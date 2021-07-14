#ifndef MODULE_H
#define MODULE_H

#include <pcp/pmapi.h>
#include <pcp/pmda.h>
#include <math.h>

typedef char* (*name_fn_t)(void);
typedef int (*init_fn_t)();
typedef void (*register_fn_t)(pmdaMetric *metrics, pmdaIndom *indoms);
typedef int (*shutdown_fn_t)(void);
typedef int (*metric_count_fn_t)(void);
typedef int (*cluster_fn_t)(void);
typedef int (*indom_count_fn_t)(void);
typedef void (*refresh_fn_t)(unsigned int item);
typedef int (*fetch_to_atom_fn_t)(unsigned int item, unsigned int inst, pmAtomValue *atom);

typedef struct {
    name_fn_t module_name;
	init_fn_t init;
    register_fn_t register_metrics;
    cluster_fn_t cluster;
    metric_count_fn_t metric_count;
    indom_count_fn_t indom_count;
    shutdown_fn_t shutdown;
    refresh_fn_t refresh;
    fetch_to_atom_fn_t fetch_to_atom;
} module;

/*
 * instance domains, need to be unique
 * a single module could use more instance domains, in which case list them all with unique numbers
 */
#define RUNQLAT_INDOM 0
#define BIOLATENCY_INDOM 1

/*
 * the pmid cluster assigned to each module
 */
#define RUNQLAT_CLUSTER 0
#define BIOLATENCY_CLUSTER 1

/**
 * list of all modules defined
 */
char *all_modules[] = {
    "runqlat",
    "biolatency"
};

/**
 * list of modules that will be loaded and served as metrics
 */
char *modules_to_load[] = {
    "biolatency",
    "runqlat"
};

#endif
