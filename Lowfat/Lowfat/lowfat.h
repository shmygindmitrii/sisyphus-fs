#pragma once

#include "lowfat_prelude.h"
#include "lowfat_defines.h"
#include "crc32_ccit.h"

#ifdef __cplusplus
extern "C" {
#endif

void lowfat_dl_acquire_next_free(int32_t * table_next, int32_t * table_prev, int32_t * last_busy, int32_t * first_free);
void lowfat_dl_free_busy_range(int32_t* table_next, int32_t* table_prev, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free);
uint32_t lowfat_dl_calculate_range_length(int32_t* table_next, int32_t first, int32_t last);

#pragma pack(push, 1)
typedef struct {
    uint64_t mtime;// = 0;
    uint32_t size;// = 0;
    uint32_t crc32;// = CRC32_CCIT_DEFAULT_VALUE;
    int32_t first_cluster;// = LF_NONE;
    int32_t last_cluster;// = LF_NONE;
    int32_t current_cluster;// = LF_NONE;   // not more than 65536 clusters
    uint16_t current_byte;// = 0;     // not more than 65536 bytes in cluster
    uint8_t locked;// = 0;
} lowfat_fileprops_t;

#define CREATE_LOWFAT_FILEPROPS(props) lowfat_fileprops_t props = { 0, 0, CRC32_CCIT_DEFAULT_VALUE, LF_NONE, LF_NONE, LF_NONE, 0, 0 };
#define RESET_LOWFAT_FILEPROPS(props) { props.mtime = 0; props.size = 0; \
                                 props.crc32 = CRC32_CCIT_DEFAULT_VALUE; \
                                 props.first_cluster = LF_NONE; \
                                 props.last_cluster = LF_NONE; \
                                 props.current_cluster = LF_NONE; \
                                 props.current_byte = 0; \
                                 props.locked = 0; }

// always refers to a place inside data, never allocates/deallocates anything, just assign and use
struct lowfat_fileinfo_t {
    char* name = nullptr;
    lowfat_fileprops_t* props = nullptr;
};
// only create is needed
#define CREATE_LOWFAT_FILEINFO(finfo, name_ptr, props_ptr) lowfat_fileinfo_t finfo; finfo.name = (char*)(name_ptr); finfo.props = (lowfat_fileprops_t*)(props_ptr);

// should be carefully deallocated
struct lowfat_filename_t {
    char* name = nullptr;
    uint32_t size = 0;
};

#define CREATE_LOWFAT_FILENAME(fname, length, __allocate) lowfat_filename_t fname; fname.name = (char*)__allocate(length); memset(fname.name, 0, length); fname.size = length;
#define DESTROY_LOWFAT_FILENAME_CONTENT(fname, __deallocate) LOWFAT_ASSERT(fname.name != NULL); __deallocate(fname.name); fname.size = 0;

enum class Lowfat_EFsInitAction {
    Reset,
    Use
};

#pragma pack(pop)

#ifdef __cplusplus
}
#endif
