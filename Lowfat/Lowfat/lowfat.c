#include "lowfat_prelude.h"
#include "lowfat_defines.h"

// tail addition
void lowfat_dl_acquire_next_free(int32_t* table_next, int32_t* table_prev, int32_t* last_busy, int32_t* first_free) {
    int32_t cur_free = *first_free;
    LOWFAT_ASSERT(table_prev[cur_free] == LF_NONE);
    *first_free = table_next[*first_free];
    if (*first_free != LF_NONE) {
        table_prev[*first_free] = LF_NONE;
    }
    LOWFAT_ASSERT(table_next[*last_busy] == LF_NONE);
    table_prev[cur_free] = *last_busy;
    table_next[*last_busy] = cur_free;
    table_next[cur_free] = LF_NONE;
    *last_busy = cur_free;
}

void lowfat_dl_free_busy_range(int32_t* table_next, int32_t* table_prev, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free) {
    // merge busy list segments
    int32_t prev = table_prev[first];
    int32_t next = table_next[last];
    table_next[prev] = next; // never LF_NONE, because of system used nodes
    if (next != LF_NONE) {
        table_prev[next] = prev;
    }
    else {
        *last_busy = prev;
    }
    // detach from busy chain and attach to free one in the beginning
    table_prev[first] = LF_NONE;
    table_next[last] = *first_free;
    if (*first_free != LF_NONE) {
        LOWFAT_ASSERT(table_prev[*first_free] == LF_NONE);
        table_prev[*first_free] = last;
    }
    *first_free = first;
}

uint32_t lowfat_dl_calculate_range_length(int32_t* table_next, int32_t first, int32_t last) {
    LOWFAT_ASSERT(first >= 0 && last >= 0);
    uint32_t node_count = 1;
    while (first != last) {
        first = table_next[first];
        node_count++;
    }
    return node_count;
}
