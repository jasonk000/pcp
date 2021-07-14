#include "module_helpers.h"

#include <pcp/pmapi.h>
#include <math.h>

void fill_instids_log2(int slot_count, pmdaInstid slots[]) {
    for(int i = 0; i < slot_count; i++) {
        char *string;
        int lower = round(pow(2, i));
        int upper = round(pow(2, i+1));
        int ret = asprintf(&string, "%d-%d", lower, upper);
        if (ret > 0) {
            slots[i].i_inst = i;
            slots[i].i_name = string;
        }
    }
}