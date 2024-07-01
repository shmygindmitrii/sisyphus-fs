#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const uint32_t CRC32_CCIT_DEFAULT_VALUE;
uint32_t crc32_ccit_update(const uint8_t* const data, size_t size, uint32_t crc);

#ifdef __cplusplus
}
#endif
