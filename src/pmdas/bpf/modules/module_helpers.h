#ifndef MODULE_HELPERS_H
#define MODULE_HELPERS_H

#include <pcp/pmapi.h>
#include <pcp/pmda.h>

/**
 * Fill a pmdaInstid table with log2 scaled values.
 *
 * The instance ID table will be filled sequentially with strings
 * "0-1", "2-3", "4-7", "8-15", "16-31", "32-63", etc
 *
 * if slot_count is > 63, it will be capped at 63
 */
void fill_instids_log2(unsigned int slot_count, pmdaInstid slots[]);

#endif