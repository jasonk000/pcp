#include "module_helpers.h"

#include <pcp/pmapi.h>
#include <math.h>

void fill_instids_log2(unsigned int slot_count, pmdaInstid slots[]) {
    if (slot_count > 63)
        slot_count = 63;

    for(int i = 0; i < slot_count; i++) {
        char *string;
        unsigned long lower = round(pow(2, i));
        unsigned long upper = round(pow(2, i+1)-1);

        // fixup
        if (i == 0)
            lower = 0;

        int ret = asprintf(&string, "%lu-%lu", lower, upper);
        if (ret > 0) {
            slots[i].i_inst = i;
            slots[i].i_name = string;
        }
    }
}
