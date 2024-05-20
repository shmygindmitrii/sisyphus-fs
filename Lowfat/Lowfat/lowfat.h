#pragma once

#include "lowfat_prelude.h"
#include "lowfat_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

void lowfat_dl_acquire_next_free(int32_t * table_next, int32_t * table_prev, int32_t * last_busy, int32_t * first_free);
void lowfat_dl_free_busy_range(int32_t* table_next, int32_t* table_prev, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free);
uint32_t lowfat_dl_calculate_range_length(int32_t* table_next, int32_t first, int32_t last);

#ifdef __cplusplus
}
#endif
