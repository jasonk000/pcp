#ifndef MODULE_H
#define MODULE_H

#include <pcp/pmapi.h>
#include <pcp/pmda.h>
#include <math.h>

typedef int (*init_fn_t)();
typedef void (*register_fn_t)(unsigned int cluster_id, pmdaMetric *metrics, pmdaIndom *indoms);
typedef int (*shutdown_fn_t)(void);
typedef unsigned int (*metric_count_fn_t)(void);
typedef void (*set_indom_serial_fn_t)(unsigned int local_indom_id, unsigned int global_id);
typedef unsigned int (*indom_count_fn_t)(void);
typedef void (*refresh_fn_t)(unsigned int item);
typedef int (*fetch_to_atom_fn_t)(unsigned int item, unsigned int inst, pmAtomValue *atom);
typedef char* (*metric_name_fn_t)(unsigned int metric);

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
     * Return the number of pmdaIndom this instance requires.
     *
     * This is used to allocate sufficient space for register_metrics call later.
     */
    indom_count_fn_t indom_count;

    /**
     * Set indom serial to support dynamic indom setup
     * 
     * Will be called "indom_count" times, start ing from 0 to "indom_count - 1", to inform
     * this module what the global indom id is for the given local id.
     */
    set_indom_serial_fn_t set_indom_serial;

    /**
     * Return the number of pmdaMetric slots this instance requires.
     *
     * This is used to allocate sufficient space for register_metrics call later.
     */
    metric_count_fn_t metric_count;

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

    /**
     * Fetch name for a metric
     */
    metric_name_fn_t metric_name;
} module;

/**
 * List of all modules defined
 */
char *all_modules[] = {
    "runqlat",
    "biolatency"
};

#endif
