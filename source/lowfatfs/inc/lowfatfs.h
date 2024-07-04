#pragma once

#include "lowfatfs_prelude.h"
#include "lowfatfs_defines.h"
#include "crc32_ccit.h"
#include "structures.h"

#define LOWFATFS_STRINGIFY(x) #x
#define LOWFATFS_TO_STRING(x) LOWFATFS_STRINGIFY(x)
#define LOWFATFS_CODELINE_TAG __FILE__ "(" LOWFATFS_TO_STRING(__LINE__)  ")"
#define LOWFATFS_MALLOC_TAG "Allocated in: " LOWFATFS_CODELINE_TAG
#define LOWFATFS_FREE_TAG "Freed in: " LOWFATFS_CODELINE_TAG

#ifdef __cplusplus
extern "C" {
#endif

void lowfatfs_dl_acquire_next_free(structures_int_pair_t* table, int32_t* last_busy, int32_t* first_free);
void lowfatfs_dl_free_busy_range(structures_int_pair_t* table, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free);
uint32_t lowfatfs_dl_calculate_range_length(const structures_int_pair_t* const table, int32_t first, int32_t last);

#pragma pack(push, 1)
typedef struct {
    uint32_t size;
    uint32_t crc32;
    int32_t first_cluster;
    int32_t last_cluster;
    int32_t current_cluster;
    uint16_t current_byte;
    uint8_t locked;
} lowfatfs_fileprops_t;

void lowfatfs_reset_fileprops(lowfatfs_fileprops_t* props);

// always refers to a place inside data, never allocates/deallocates anything, just assign and use
typedef struct {
    char* name;
    lowfatfs_fileprops_t* props;
} lowfatfs_fileinfo_t;

// only create is needed, it is purely assignment of correct addresses into a single variable
lowfatfs_fileinfo_t lowfatfs_create_fileinfo(void* name_ptr, void* props_ptr);

typedef struct {
    uint32_t _cluster_size;
    uint32_t _cluster_count;
    uint32_t _filename_length;
    uint32_t _used_memory;
    uint32_t _used_cluster_count;
    uint32_t _file_count; // 0
    int32_t  _filename_table_busy_tail; // LOWFATFS_NONE
    int32_t  _filename_table_free_head; // 0
    int32_t  _data_table_busy_tail; // LOWFATFS_NONE
    int32_t  _data_table_free_head; // 0
} lowfatfs_header;

typedef struct {
    uint32_t _total_size;
    uint32_t _system_used_size;
    uint32_t _system_used_clusters;
    uint32_t _last_system_cluster;
    uint32_t _clusters_touched;
} lowfatfs_info;

typedef struct {
    // this is the only real data
    uint8_t* _data; // of total_size
    // inside of _data
    lowfatfs_header* _header;
    // arrays of cluster_count elements
    uint16_t* _cluster_flags; // 0
    uint8_t* _filenames;
    uint8_t* _fileprops;
    structures_int_pair_t* _filename_table;
    structures_int_pair_t* _data_table;
    // because this part do not change, no need to save it into _data
    lowfatfs_info _info;
} lowfatfs;
#pragma pack(pop)

// fs instance creation/destruction
lowfatfs* lowfatfs_create_instance(uint32_t cluster_size, uint32_t cluster_count, uint32_t filename_length, uint8_t* mem);
void lowfatfs_set_instance_addresses(lowfatfs* fs_ptr);
void lowfatfs_reset_instance(lowfatfs* fs_ptr);
void lowfatfs_destroy_instance(lowfatfs* fs_ptr);
// fs instance info
uint32_t lowfatfs_free_mem_size(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_free_available_mem_size(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_file_count(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_filename_length(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_cluster_size(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_cluster_count(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_total_size(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_system_used_clusters(const lowfatfs* const fs_ptr);
uint32_t lowfatfs_system_used_size(const lowfatfs* const fs_ptr);
// file API
int32_t lowfatfs_open_file(lowfatfs* fs_ptr, const char* filename, char mode);
int32_t lowfatfs_read_file(lowfatfs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd);
int32_t lowfatfs_write_file(lowfatfs* fs_ptr, const uint8_t* const buf, uint32_t elem_size, uint32_t count, int32_t fd);
int32_t lowfatfs_close_file(lowfatfs* fs_ptr, int32_t fd);
uint32_t lowfatfs_remove_file(lowfatfs* fs_ptr, int32_t fd);
int32_t lowfatfs_remove_file_str(lowfatfs* fs_ptr, const char* filename);
int32_t lowfatfs_find_file(lowfatfs* fs_ptr, const char* filename);
lowfatfs_fileinfo_t lowfatfs_file_stat(lowfatfs* fs_ptr, int32_t fd);
lowfatfs_fileinfo_t lowfatfs_file_stat_str(lowfatfs* fs_ptr, const char* name);
// abstract walking over changed data, including system sectors
int32_t lowfatfs_walk_over_changed_data(lowfatfs* fs_ptr, size_t(*procedure)(void* data, size_t size));
// walk over all files if needed
int32_t lowfatfs_get_descriptor(const lowfatfs* const fs_ptr, uint32_t file_idx);
uint32_t lowfatfs_walk_over_all_files(const lowfatfs* const fs_ptr, void* arg, void(*procedure)(int32_t fd, void* data));

#ifdef __cplusplus
}
#endif
