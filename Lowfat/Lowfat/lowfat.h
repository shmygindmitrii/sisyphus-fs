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
    uint64_t mtime;
    uint32_t size;
    uint32_t crc32;
    int32_t first_cluster;
    int32_t last_cluster;
    int32_t current_cluster;
    uint16_t current_byte;
    uint8_t locked;
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
typedef struct {
    char* name;
    lowfat_fileprops_t* props;
} lowfat_fileinfo_t;

// only create is needed
#define CREATE_LOWFAT_FILEINFO(finfo, name_ptr, props_ptr) lowfat_fileinfo_t finfo; finfo.name = (char*)(name_ptr); finfo.props = (lowfat_fileprops_t*)(props_ptr);

enum Lowfat_EFsInitAction {
    Reset,
    Use
};

typedef struct {
    // this is the only real data
    uint8_t* _data; // of total_size
    //
    uint32_t* _cluster_size;
    uint32_t* _cluster_count;
    uint32_t* _filename_length;
    uint32_t* _used_memory;
    uint32_t* _used_cluster_count;
    uint32_t* _file_count; // 0
    int32_t* _filename_table_busy_tail; // LF_NONE
    int32_t* _filename_table_free_head; // 0
    int32_t* _data_table_busy_tail; // LF_NONE
    int32_t* _data_table_free_head; // 0
    // arrays of cluster_count elements
    uint8_t* _filenames;
    uint8_t* _fileprops;
    int32_t* _filename_table_next;
    int32_t* _filename_table_prev;
    int32_t* _data_table_next;
    int32_t* _data_table_prev;
    // because this part do not change, no need to save it into _data
    uint32_t _total_size;
    uint32_t _system_used_size;
    uint32_t _system_used_clusters;
    uint32_t _last_system_cluster;
} lowfat_fs;
#pragma pack(pop)

extern const uint64_t LOWFAT_FS_DUMP_BEGIN_MARKER;
extern const uint64_t LOWFAT_FS_DUMP_END_MARKER;

// fs instance creation/destruction
lowfat_fs* lowfat_fs_create_instance(uint32_t cluster_size, uint32_t cluster_count, uint32_t filename_length, uint8_t* mem, void* (*__allocate)(size_t size));
void lowfat_fs_set_instance_addresses(lowfat_fs* fs_ptr);
void lowfat_fs_reset_instance(lowfat_fs* fs_ptr);
void lowfat_fs_destroy_instance(lowfat_fs* fs_ptr, void(*__deallocate)(void* ptr));
// fs instance info
uint32_t lowfat_fs_free_mem_size(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_free_available_mem_size(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_file_count(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_filename_length(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_cluster_size(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_cluster_count(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_total_size(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_system_used_clusters(lowfat_fs* fs_ptr);
uint32_t lowfat_fs_system_used_size(lowfat_fs* fs_ptr);
// file API
int32_t lowfat_fs_open_file(lowfat_fs* fs_ptr, const char* filename, char mode);
int32_t lowfat_fs_read_file(lowfat_fs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd);
int32_t lowfat_fs_write_file(lowfat_fs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd);
int32_t lowfat_fs_close_file(lowfat_fs* fs_ptr, int32_t fd);
int32_t lowfat_fs_remove_file(lowfat_fs* fs_ptr, int32_t fd);
int32_t lowfat_fs_remove_file_str(lowfat_fs* fs_ptr, const char* filename);
int32_t lowfat_fs_find_file(lowfat_fs* fs_ptr, const char* filename);
lowfat_fileinfo_t lowfat_fs_file_stat(lowfat_fs* fs_ptr, int32_t fd);
lowfat_fileinfo_t lowfat_fs_file_stat_str(lowfat_fs* fs_ptr, const char* name);

#ifdef __cplusplus
}
#endif
