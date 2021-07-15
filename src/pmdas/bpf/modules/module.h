#ifndef MODULE_H
#define MODULE_H

#include <pcp/pmapi.h>
#include <pcp/pmda.h>
#include <math.h>

typedef char* (*name_fn_t)(void);
typedef int (*init_fn_t)();
typedef void (*register_fn_t)(pmdaMetric *metrics, pmdaIndom *indoms);
typedef int (*shutdown_fn_t)(void);
typedef unsigned int (*metric_count_fn_t)(void);
typedef unsigned int (*cluster_fn_t)(void);
typedef unsigned int (*indom_count_fn_t)(void);
typedef void (*refresh_fn_t)(unsigned int item);
typedef int (*fetch_to_atom_fn_t)(unsigned int item, unsigned int inst, pmAtomValue *atom);

/**
 * Module layer interface struct.
 *
 * Modules should be shared object files (.so) and have a single well-known entry
 * point 'load_module'. The load_module call for each module should return a populated
 * module struct.
 *
 * Functions cannot be null. Modules need to be prepared to respond to all of these
 * calls; even if they are a noop they should provide default behaviour as they will
 * be called.
 */
typedef struct module {
    /**
     * Returns a pointer to the name of the module.
     *
     * Caller should not free() this as it is statically allocated.
     */
    name_fn_t module_name;

    /**
     * Return the number of pmdaIndom this instance requires.
     *
     * This is used to allocate sufficient space for register_metrics call later.
     */
    indom_count_fn_t indom_count;

    /**
     * Return the number of pmdaMetric slots this instance requires.
     *
     * This is used to allocate sufficient space for register_metrics call later.
     */
    metric_count_fn_t metric_count;

    /**
     * Return the cluster number for this module.
     *
     * The cluster here must match the definitions in PMNS.
     */
    cluster_fn_t cluster;

    /**
     * Callback to have module fill in pmdaMetric and pmdaIndom records.
     *
     * The module is passed an array pointer for pmdaMetric and pmdaIndom records; the
     * module should fill the elements sequentially. It is important that indom_count()
     * and metric_count() calls return the correct number so that there is correct
     * space allocated.
     *
     * The values here must match the definitions in PMNS.
     */
    register_fn_t register_metrics;

    /**
     * Initialise a module.
     *
     * @return 0 if no issues, non-zero to indicate errors.
     */
	init_fn_t init;

    /**
     * Release any resources associated with the module.
     *
     * TODO Currently never called
     */
    shutdown_fn_t shutdown;

    /**
     * Pre-fetch refresh call issued by PMCD.
     *
     * This is a good time to refresh indom table, or load any metrics that are more
     * efficiently fetched in bulk.
     */
    refresh_fn_t refresh;

    /**
     * Fetch individual metric for a module, akin to the pmdaFetchCallback.
     *
     * A module can be called for fetch without being initialised, it should respond
     * with PMDA_FETCH_NOVALUES. This is the module's responsibility.
     */
    fetch_to_atom_fn_t fetch_to_atom;
} module;

/**
 * Instance domains, need to be unique across all modules.
 *
 * A single module could use more instance domains, in which case list them all with
 * unique numbers.
 */
#define RUNQLAT_INDOM 0
#define BIOLATENCY_INDOM 1

/**
 * the pmid cluster assigned to each module, unique for each module.
 */
#define RUNQLAT_CLUSTER 0
#define BIOLATENCY_CLUSTER 1

/**
 * List of all modules defined
 */
char *all_modules[] = {
    "runqlat",
    "biolatency"
};

#endif
