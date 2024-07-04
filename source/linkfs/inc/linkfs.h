#pragma once

#include "linkfs_prelude.h"
#include "linkfs_defines.h"
#include "crc32_ccit.h"

#define LINKFS_STRINGIFY(x) #x
#define LINKFS_TO_STRING(x) LINKFS_STRINGIFY(x)
#define LINKFS_CODELINE_TAG __FILE__ "(" LINKFS_TO_STRING(__LINE__)  ")"
#define LINKFS_MALLOC_TAG "Allocated in: " LINKFS_CODELINE_TAG
#define LINKFS_FREE_TAG "Freed in: " LINKFS_CODELINE_TAG

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t length;
    char* content;
} linkfs_string_t;

typedef struct {
    size_t size;
    uint8_t* data;
} linkfs_memory_block_t;

typedef struct linkfs_cluster {
    linkfs_memory_block_t* block;
    struct linkfs_cluster* next;
} linkfs_cluster_t;

typedef struct {
    size_t block_size;
    size_t block_count;
    size_t size;
    size_t allocated;
    uint32_t crc;
    size_t current_index;
    size_t current_byte;
    uint16_t flags;
} linkfs_file_props_t;

typedef struct {
    linkfs_string_t* filename;
    linkfs_cluster_t* start;
    linkfs_cluster_t* current;
    linkfs_file_props_t props;
} linkfs_file_t;

typedef struct {
    size_t capacity;
    size_t size;
    linkfs_file_t** entries;
} linkfs_file_vector_t;

typedef struct {
    linkfs_file_vector_t* files;
} linkfs;

// string

linkfs_string_t* linkfs_create_string(const char* line, const char* malloc_tag);
void linkfs_destroy_string(linkfs_string_t* str_ptr, const char* free_tag);

// memory block 

linkfs_memory_block_t* linkfs_create_memory_block(size_t size, const char* malloc_tag);
void linkfs_destroy_memory_block(linkfs_memory_block_t* block_ptr, const char* free_tag);

// cluster

linkfs_cluster_t* linkfs_create_cluster(size_t block_size, const char* malloc_tag);
void linkfs_destroy_cluster(linkfs_cluster_t* cluster_ptr, const char* free_tag);

// file

linkfs_file_t* linkfs_create_file(const char* filename, size_t block_size, const char* malloc_tag);
size_t linkfs_file_binary_size(const linkfs_file_t* const file_ptr);
linkfs_memory_block_t* linkfs_create_memory_block_from_file(const linkfs_file_t* const file_ptr, const char* malloc_tag);
linkfs_file_t* linkfs_create_file_from_memory_block(const linkfs_memory_block_t* const block_ptr, const char* malloc_tag);
uint32_t linkfs_calculate_crc(const linkfs_file_t* const file_ptr);
void linkfs_destroy_file(linkfs_file_t* file_ptr, const char* free_tag);

// file vector

linkfs_file_vector_t* linkfs_create_file_vector(const char* malloc_tag);
void linkfs_file_vector_reserve(linkfs_file_vector_t* file_vector_ptr, const size_t new_capacity, const char* memory_tag);
linkfs_file_t* linkfs_file_vector_find(const linkfs_file_vector_t* const file_vector_ptr, const char* filename);
linkfs_file_t* linkfs_file_vector_append_new(linkfs_file_vector_t* file_vector_ptr, const char* filename, size_t block_size, const char* malloc_tag);
void linkfs_file_vector_append(linkfs_file_vector_t* file_vector_ptr, linkfs_file_t* file_ptr, const char* malloc_tag);
void linkfs_destroy_file_vector(linkfs_file_vector_t* file_vector_ptr, const char* free_tag);

// fs

linkfs* linkfs_create_instance(const char* malloc_tag);
void linkfs_destroy_instance(linkfs* fs_ptr, const char* free_tag);

// fs info

size_t linkfs_file_count(const linkfs* const fs_ptr);
size_t linkfs_total_size(const linkfs* const fs_ptr);

// file API

size_t linkfs_read_file(linkfs_file_t* file_ptr, const linkfs_memory_block_t* const buffer);
size_t linkfs_write_file(linkfs_file_t* file_ptr, const linkfs_memory_block_t* const buffer, const char* malloc_tag);
void linkfs_reset_file_cursor(linkfs_file_t* file_ptr);
linkfs_file_t* linkfs_open_new_file(linkfs* fs_ptr, const char* filename, size_t block_size, const char* malloc_tag);
linkfs_file_t* linkfs_open_file(linkfs* fs_ptr, const char* filename, char mode, const char* memory_tag);
int32_t linkfs_close_file(linkfs_file_t* file_ptr);
uint32_t linkfs_remove_file(linkfs* fs_ptr, const linkfs_file_t* const file_ptr, const char* free_tag);
int32_t linkfs_remove_file_str(linkfs* fs_ptr, const char* filename, const char* free_tag);
linkfs_file_t* linkfs_find_file(const linkfs* const fs_ptr, const char* filename);
// walk over all files if needed
size_t linkfs_walk_over_all_files(const linkfs* const fs_ptr, void* arg, void(*procedure)(linkfs_file_t* file_ptr, void* data));

// binary form

linkfs_memory_block_t* linkfs_to_memory_block(const linkfs* const fs_ptr, const char* malloc_tag);
linkfs* linkfs_from_memory_block(const linkfs_memory_block_t* const block_ptr, const char* malloc_tag);

#ifdef __cplusplus
}
#endif
