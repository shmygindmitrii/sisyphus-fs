#include "lowfatfs_prelude.h"
#include "lowfatfs_defines.h"
#include "lowfatfs.h"

#ifdef LOWFATFS_CUSTOM_ALLOCATOR
extern void* user_malloc(size_t size, const char* malloc_tag);
extern void user_free(void*, const char* free_tag);
#define LOWFATFS_ALLOC user_malloc
#define LOWFATFS_FREE user_free
#else
#pragma message("Warning: use default malloc and free")
static void* default_malloc(size_t size, const char* malloc_tag) {
    (void)malloc_tag;
    return malloc(size);
}
static void default_free(void* ptr, const char* free_tag) {
    (void)free_tag;
    free(ptr);
}
#define LOWFATFS_ALLOC default_malloc
#define LOWFATFS_FREE default_free
#endif

// double linked-list functions
#define PAIR_NEXT second
#define PAIR_PREV first
// tail addition
void lowfatfs_dl_acquire_next_free(structures_int_pair_t* table, int32_t* last_busy, int32_t* first_free) {
    int32_t cur_free = *first_free;
    LOWFATFS_ASSERT(table[cur_free].PAIR_PREV == LOWFATFS_NONE);
    *first_free = table[*first_free].PAIR_NEXT;
    if (*first_free != LOWFATFS_NONE) {
        table[*first_free].PAIR_PREV = LOWFATFS_NONE;
    }
    LOWFATFS_ASSERT(table[*last_busy].PAIR_NEXT == LOWFATFS_NONE);
    table[cur_free].PAIR_PREV = *last_busy;
    table[*last_busy].PAIR_NEXT = cur_free;
    table[cur_free].PAIR_NEXT = LOWFATFS_NONE;
    *last_busy = cur_free;
}

void lowfatfs_dl_free_busy_range(structures_int_pair_t* table, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free) {
    // merge busy list segments
    int32_t prev = table[first].PAIR_PREV;
    int32_t next = table[last].PAIR_NEXT;
    table[prev].PAIR_NEXT = next; // never LOWFATFS_NONE, because of system used nodes
    if (next != LOWFATFS_NONE) {
        table[next].PAIR_PREV = prev;
    }
    else {
        *last_busy = prev;
    }
    // detach from busy chain and attach to free one in the beginning
    table[first].PAIR_PREV = LOWFATFS_NONE;
    table[last].PAIR_NEXT = *first_free;
    if (*first_free != LOWFATFS_NONE) {
        LOWFATFS_ASSERT(table[*first_free].PAIR_PREV == LOWFATFS_NONE);
        table[*first_free].PAIR_PREV = last;
    }
    *first_free = first;
}

uint32_t lowfatfs_dl_calculate_range_length(const structures_int_pair_t* const table, int32_t first, int32_t last) {
    LOWFATFS_ASSERT(first >= 0 && last >= 0);
    uint32_t node_count = 1;
    while (first != last) {
        first = table[first].PAIR_NEXT;
        node_count++;
    }
    return node_count;
}

// fileprops 

void lowfatfs_reset_fileprops(lowfatfs_fileprops_t* props) {
    props->size = 0;
    props->crc32 = 0;
    props->first_cluster = LOWFATFS_NONE;
    props->last_cluster = LOWFATFS_NONE;
    props->current_cluster = LOWFATFS_NONE;
    props->current_byte = 0;
    props->locked = 0;
}

// fileinfo

lowfatfs_fileinfo_t lowfatfs_create_fileinfo(void* name_ptr, void* props_ptr) {
    lowfatfs_fileinfo_t finfo;
    finfo.name = (char*)(name_ptr);
    finfo.props = (lowfatfs_fileprops_t*)(props_ptr);
    return finfo;
}

// fs

lowfatfs* lowfatfs_create_instance(uint32_t cluster_size, uint32_t cluster_count, uint32_t filename_length, uint8_t* mem) {
    lowfatfs* fs_ptr = (lowfatfs*)LOWFATFS_ALLOC(sizeof(lowfatfs), LOWFATFS_MALLOC_TAG);
    fs_ptr->_data = mem;
    fs_ptr->_header = (lowfatfs_header*)mem;
    fs_ptr->_info._total_size = cluster_count * cluster_size;

    fs_ptr->_header->_cluster_size = cluster_size;
    fs_ptr->_header->_cluster_count = cluster_count;
    fs_ptr->_header->_filename_length = filename_length;

    fs_ptr->_info._system_used_size = sizeof(lowfatfs_header) + (sizeof(lowfatfs_fileprops_t) + filename_length + sizeof(int32_t) * 4 + sizeof(uint16_t)) * cluster_count;
    fs_ptr->_info._system_used_clusters = fs_ptr->_info._system_used_size / cluster_size + (fs_ptr->_info._system_used_size % cluster_size > 0);
    fs_ptr->_info._last_system_cluster = fs_ptr->_info._system_used_clusters - 1;
    fs_ptr->_info._clusters_touched = 0;
    LOWFATFS_ASSERT(fs_ptr->_info._system_used_clusters < cluster_count);
    return fs_ptr;
}

void lowfatfs_set_instance_addresses(lowfatfs* fs_ptr) {
    // 40 bytes used for common fs values
    const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
    const uint32_t fileinfo_size = fileinfo_stride * fs_ptr->_header->_cluster_count;
    fs_ptr->_filenames = fs_ptr->_data + sizeof(lowfatfs_header);
    fs_ptr->_fileprops = fs_ptr->_data + sizeof(lowfatfs_header) + fs_ptr->_header->_filename_length;
    fs_ptr->_filename_table = (structures_int_pair_t*)(fs_ptr->_data + sizeof(lowfatfs_header) + fileinfo_size);
    fs_ptr->_data_table = fs_ptr->_filename_table + fs_ptr->_header->_cluster_count;
    fs_ptr->_cluster_flags = (uint16_t*)(fs_ptr->_data_table + fs_ptr->_header->_cluster_count);
}

void lowfatfs_reset_instance(lowfatfs* fs_ptr) {
    fs_ptr->_header->_used_memory = fs_ptr->_info._system_used_size;
    fs_ptr->_header->_used_cluster_count = fs_ptr->_info._system_used_clusters;
    fs_ptr->_header->_filename_table_busy_tail = LOWFATFS_NONE;
    fs_ptr->_header->_data_table_busy_tail = LOWFATFS_NONE;
    const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
    for (uint32_t i = 0; i < fs_ptr->_header->_cluster_count; i++) {
        memset(fs_ptr->_filenames + i * fileinfo_stride, 0, fs_ptr->_header->_filename_length);
        lowfatfs_fileprops_t* props_i = (lowfatfs_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        lowfatfs_reset_fileprops(props_i);
        fs_ptr->_filename_table[i].PAIR_NEXT = i + 1;
        fs_ptr->_filename_table[i].PAIR_PREV = i - 1;
        fs_ptr->_data_table[i].PAIR_NEXT = i + 1;
        fs_ptr->_data_table[i].PAIR_PREV = i - 1;
        fs_ptr->_cluster_flags[i] = 0;
    }
    fs_ptr->_filename_table[fs_ptr->_header->_cluster_count - 1].PAIR_NEXT = LOWFATFS_NONE;
    fs_ptr->_header->_filename_table_busy_tail = fs_ptr->_info._last_system_cluster;
    fs_ptr->_header->_filename_table_free_head = fs_ptr->_info._last_system_cluster + 1;
    fs_ptr->_filename_table[fs_ptr->_header->_filename_table_busy_tail].PAIR_NEXT = LOWFATFS_NONE;
    fs_ptr->_filename_table[fs_ptr->_header->_filename_table_free_head].PAIR_PREV = LOWFATFS_NONE;

    for (uint32_t i = 0; i < fs_ptr->_info._system_used_clusters; i++) {
        snprintf((char*)(fs_ptr->_filenames + i * fileinfo_stride), fs_ptr->_header->_filename_length, "SYSTEM%d", i);
        lowfatfs_fileprops_t* props_i = (lowfatfs_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        props_i->size = fs_ptr->_header->_cluster_size;
    }

    fs_ptr->_data_table[fs_ptr->_header->_cluster_count - 1].PAIR_NEXT = LOWFATFS_NONE;
    fs_ptr->_header->_data_table_busy_tail = fs_ptr->_info._last_system_cluster;
    fs_ptr->_header->_data_table_free_head = fs_ptr->_info._last_system_cluster + 1;
    fs_ptr->_data_table[fs_ptr->_header->_data_table_busy_tail].PAIR_NEXT = LOWFATFS_NONE;
    fs_ptr->_data_table[fs_ptr->_header->_data_table_free_head].PAIR_PREV = LOWFATFS_NONE;
}

void lowfatfs_destroy_instance(lowfatfs* fs_ptr) {
    LOWFATFS_FREE(fs_ptr, LOWFATFS_FREE_TAG);
}

static inline void lowfatfs_increment_touched_clusters_count(lowfatfs* fs_ptr, uint32_t clusters) {
    if (fs_ptr->_info._clusters_touched == 0) {
        fs_ptr->_info._clusters_touched += fs_ptr->_info._system_used_clusters;
    }
    fs_ptr->_info._clusters_touched += clusters;
}

int32_t lowfatfs_open_file(lowfatfs* fs_ptr, const char* filename, char mode) {
    if (filename == NULL) {
        return LOWFATFS_ERROR_FILE_NAME_NULL;
    }
    size_t filename_len = strlen(filename);
    if (filename_len > (fs_ptr->_header->_filename_length - 1)) {
        return LOWFATFS_ERROR_FILE_NAME_TOO_LONG;
    }
    int32_t fd = lowfatfs_find_file(fs_ptr, filename);
    if (fd >= 0 && fd < (int32_t)fs_ptr->_info._system_used_clusters) {
        return LOWFATFS_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
    if (mode == 'r') {
        if (fd >= 0) {
            lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
            fi.props->locked |= LOWFATFS_FILE_READ;
        }
        return fd;
    }
    else if (mode == 'w') {
        if (fd >= 0) {
            // remove existing
            lowfatfs_remove_file(fs_ptr, fd);
            fd = LOWFATFS_ERROR_FILE_NOT_FOUND;
        }
        if (fd == LOWFATFS_ERROR_FILE_ALREADY_OPENED) {
            return LOWFATFS_ERROR_FILE_ALREADY_OPENED;
        }
        if (fs_ptr->_header->_data_table_free_head == LOWFATFS_NONE) {
            return LOWFATFS_ERROR_SPACE_ENDED;
        }
        LOWFATFS_ASSERT(fd == LOWFATFS_ERROR_FILE_NOT_FOUND);
        // LOWFATFS_FILE_ERROR_NOT_FOUND - create new
        lowfatfs_dl_acquire_next_free(fs_ptr->_filename_table, &fs_ptr->_header->_filename_table_busy_tail, &fs_ptr->_header->_filename_table_free_head);
        fd = fs_ptr->_header->_filename_table_busy_tail;
        // put busy node to the head of list
        lowfatfs_dl_acquire_next_free(fs_ptr->_data_table, &fs_ptr->_header->_data_table_busy_tail, &fs_ptr->_header->_data_table_free_head);
        fs_ptr->_header->_used_cluster_count = fs_ptr->_header->_used_cluster_count + 1;
        // add to _fileinfos first free first_cluster
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        sprintf_s(fi.name, fs_ptr->_header->_filename_length, filename);
        fi.props->size = 0;
        fi.props->first_cluster = fs_ptr->_header->_data_table_busy_tail;
        fi.props->last_cluster = fs_ptr->_header->_data_table_busy_tail;
        fi.props->current_cluster = fs_ptr->_header->_data_table_busy_tail;
        fi.props->current_byte = 0;
        fi.props->locked = (LOWFATFS_FILE_LOCKED | LOWFATFS_FILE_WRITE);
        fs_ptr->_cluster_flags[fi.props->last_cluster] |= LOWFATFS_CLUSTER_TOUCHED;
#if defined(LOWFATFS_VERBOSITY) && LOWFATFS_VERBOSITY == LOWFATFS_VERBOSITY_MAX
        printf("OPEN[%d]: touched cluster %d \n", fs_ptr->_header->_file_count, fi.props->last_cluster);
#endif
        fs_ptr->_header->_file_count++;
        lowfatfs_increment_touched_clusters_count(fs_ptr, 1);
        return fd;
    }
    return LOWFATFS_ERROR_FILE_WRONG_MODE;
}

int32_t lowfatfs_read_file(lowfatfs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0 && fd < (int32_t)fs_ptr->_info._system_used_clusters) {
        return LOWFATFS_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
    if (fd > (int32_t)fs_ptr->_info._last_system_cluster) {
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        uint32_t read_size = elem_size * count;
        if (read_size > fi.props->size) {
            return LOWFATFS_ERROR_FILE_READ_SIZE_OVERFLOW;
        }
        uint32_t buf_offset = 0;
        while (read_size > 0) {
            uint32_t mem_can_read = fs_ptr->_header->_cluster_size - fi.props->current_byte;
            if (mem_can_read == 0) {
                fi.props->current_cluster = fs_ptr->_data_table[fi.props->current_cluster].PAIR_NEXT;
                fi.props->current_byte = 0;
                mem_can_read = fs_ptr->_header->_cluster_size;
            }
            if (mem_can_read > read_size) {
                mem_can_read = read_size;
            }
            //
            uint32_t offset = fi.props->current_cluster * fs_ptr->_header->_cluster_size + fi.props->current_byte;
            memcpy(buf + buf_offset, &fs_ptr->_data[offset], mem_can_read);
            //
            fi.props->current_byte += (uint16_t)mem_can_read;
            buf_offset += mem_can_read;
            read_size -= mem_can_read;
        }
        return LOWFATFS_OK;
    }
    return LOWFATFS_ERROR_FILE_NOT_FOUND;
}

int32_t lowfatfs_write_file(lowfatfs* fs_ptr, const uint8_t* const buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0) {
        // always write new
        int32_t total_write_size = elem_size * count;
        uint32_t buf_offset = 0;
        const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        const uint32_t prev_used_clusters = fs_ptr->_header->_used_cluster_count;
        while (total_write_size > 0) {
            int32_t mem_can_write = fs_ptr->_header->_cluster_size - fi.props->current_byte;
            if (mem_can_write == 0) {
                // go to the next cluster
                LOWFATFS_ASSERT(fs_ptr->_header->_data_table_free_head != LOWFATFS_NONE);
                if (fs_ptr->_header->_data_table_free_head == LOWFATFS_NONE) {
                    return LOWFATFS_ERROR_SPACE_ENDED;
                }
                lowfatfs_dl_acquire_next_free(fs_ptr->_data_table, &fs_ptr->_header->_data_table_busy_tail, &fs_ptr->_header->_data_table_free_head);
                fi.props->last_cluster = fs_ptr->_header->_data_table_busy_tail;
                fi.props->current_byte = 0;
                mem_can_write = fs_ptr->_header->_cluster_size;
                fs_ptr->_header->_used_cluster_count++;
                fs_ptr->_cluster_flags[fi.props->last_cluster] |= LOWFATFS_CLUSTER_TOUCHED;
#if LOWFATFS_VERBOSITY == LOWFATFS_VERBOSITY_MAX
                printf("WRITE[%d]: touched cluster %d \n", fd, fi.props->last_cluster);
#endif
            }
            if (mem_can_write >= total_write_size) {
                mem_can_write = total_write_size;
            }
            uint32_t offset = fi.props->last_cluster * fs_ptr->_header->_cluster_size + fi.props->current_byte;
            //
            memcpy(fs_ptr->_data + offset, buf + buf_offset, mem_can_write);
            //
            fi.props->current_byte += (uint16_t)mem_can_write;
            fi.props->size += mem_can_write;
            buf_offset += mem_can_write;
            total_write_size -= mem_can_write;
        }
        fi.props->crc32 = crc32_ccit_update(buf, elem_size * count, fi.props->crc32 ^ 0xFFFFFFFF);
        fs_ptr->_header->_used_memory += elem_size * count;
        lowfatfs_increment_touched_clusters_count(fs_ptr, fs_ptr->_header->_used_cluster_count - prev_used_clusters);
        return count;
    }
    else {
#if _DEBUG
        __debugbreak();
#endif
        return -1;
    }
}

int32_t lowfatfs_close_file(lowfatfs* fs_ptr, int32_t fd) {
    if (fd >= 0) {
        const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        fi.props->current_cluster = fi.props->first_cluster;
        fi.props->current_byte = 0;
#if LOWFATFS_FORBID_EMPTY_FILES
        LOWFATFS_ASSERT(fi.props->size != 0);
#endif
#if defined(LOWFATFS_VERBOSITY) && LOWFATFS_VERBOSITY == LOWFATFS_VERBOSITY_DETAILED
        if (fi.props->locked & LOWFATFS_FILE_WRITE) {
            printf("Close descriptor %d of size %u and crc32 = %u, space remains = %u bytes\n", fd, fi.props->size, fi.props->crc32, lowfatfs_free_available_mem_size(fs_ptr));
        }
        else {
            printf("Close descriptor %d of size %u and crc32 = %u\n", fd, fi.props->size, fi.props->crc32);
        }
#endif
        fi.props->locked &= LOWFATFS_FILE_LRW_INV_MASK;
        return LOWFATFS_OK;
    }
    return fd;
}

uint32_t lowfatfs_remove_file(lowfatfs* fs_ptr, int32_t fd) {
    LOWFATFS_ASSERT(fd >= 0 && fd < (int32_t)fs_ptr->_header->_cluster_count);
    if (fd >= 0 && fd < (int32_t)fs_ptr->_header->_cluster_count) {
        // busy clusters handle
        const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        int32_t first_cluster = fi.props->first_cluster;
        int32_t last_cluster = fi.props->last_cluster;
        uint32_t freed_clusters = lowfatfs_dl_calculate_range_length(fs_ptr->_data_table, first_cluster, last_cluster);
        fs_ptr->_header->_used_cluster_count -= freed_clusters;
        lowfatfs_dl_free_busy_range(fs_ptr->_data_table, first_cluster, last_cluster, &fs_ptr->_header->_data_table_busy_tail, &fs_ptr->_header->_data_table_free_head);
        // 
        lowfatfs_dl_free_busy_range(fs_ptr->_filename_table, fd, fd, &fs_ptr->_header->_filename_table_busy_tail, &fs_ptr->_header->_filename_table_free_head);
        // reset properties
        fs_ptr->_header->_used_memory -= fi.props->size;
#if defined(LOWFATFS_VERBOSITY) && LOWFATFS_VERBOSITY == LOWFATFS_VERBOSITY_DETAILED
        printf("Remove file '%s' of size %u\n", fi.name, fi.props->size);
#endif
        memset(fi.name, 0, fs_ptr->_header->_filename_length);
        lowfatfs_reset_fileprops(fi.props);
        fs_ptr->_header->_file_count--;
        lowfatfs_increment_touched_clusters_count(fs_ptr, 0); // add _system_used_clusters if not added already
        return freed_clusters;
    }
    else {
        return 0;
    }
}

int32_t lowfatfs_remove_file_str(lowfatfs* fs_ptr, const char* filename) {
    int32_t fd = lowfatfs_find_file(fs_ptr, filename);
    if (fd >= LOWFATFS_OK) {
        return lowfatfs_remove_file(fs_ptr, fd);
    }
    return fd;
}

int32_t lowfatfs_find_file(lowfatfs* fs_ptr, const char* filename) {
    // linear search
    int32_t busy_head = fs_ptr->_filename_table[fs_ptr->_info._last_system_cluster].PAIR_NEXT;
    const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
    while (busy_head != LOWFATFS_NONE) {
        if (strcmp((char*)(fs_ptr->_filenames + busy_head * fileinfo_stride), filename) == 0) {
            return busy_head;
        }
        busy_head = fs_ptr->_filename_table[busy_head].PAIR_NEXT;
    }
    return LOWFATFS_ERROR_FILE_NOT_FOUND;
}

lowfatfs_fileinfo_t lowfatfs_file_stat(lowfatfs* fs_ptr, int32_t fd) {
    LOWFATFS_ASSERT(fd >= 0 && fd < (int32_t)fs_ptr->_header->_cluster_count);
    if (fd >= 0 && fd < (int32_t)fs_ptr->_header->_cluster_count) {
        const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    else {
        lowfatfs_fileinfo_t empty = lowfatfs_create_fileinfo(NULL, NULL);
        return empty;
    }
}

uint32_t lowfatfs_free_mem_size(const lowfatfs* const fs_ptr) {
    // real free space, that includes unused clusters memory
    return fs_ptr->_info._total_size - fs_ptr->_header->_used_memory;
}

lowfatfs_fileinfo_t lowfatfs_file_stat_str(lowfatfs* fs_ptr, const char* name) {
    int fd = lowfatfs_find_file(fs_ptr, name);
    if (fd != LOWFATFS_ERROR_FILE_NOT_FOUND) {
        const uint32_t fileinfo_stride = sizeof(lowfatfs_fileprops_t) + fs_ptr->_header->_filename_length;
        lowfatfs_fileinfo_t fi = lowfatfs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    lowfatfs_fileinfo_t empty = lowfatfs_create_fileinfo(NULL, NULL);
    return empty;
}

uint32_t lowfatfs_free_available_mem_size(const lowfatfs* const fs_ptr) {
    // real writable amount of memory
    return (fs_ptr->_header->_cluster_count - fs_ptr->_header->_used_cluster_count) * fs_ptr->_header->_cluster_size;
}

uint32_t lowfatfs_file_count(const lowfatfs* const fs_ptr) {
    return fs_ptr->_header->_file_count;
}

uint32_t lowfatfs_filename_length(const lowfatfs* const fs_ptr) {
    return fs_ptr->_header->_filename_length;
}

uint32_t lowfatfs_cluster_size(const lowfatfs* const fs_ptr) {
    return fs_ptr->_header->_cluster_size;
}

uint32_t lowfatfs_cluster_count(const lowfatfs* const fs_ptr) {
    return fs_ptr->_header->_cluster_count;
}

uint32_t lowfatfs_total_size(const lowfatfs* const fs_ptr) {
    return fs_ptr->_header->_cluster_count * fs_ptr->_header->_cluster_size;
}

uint32_t lowfatfs_system_used_clusters(const lowfatfs* const fs_ptr) {
    return fs_ptr->_info._system_used_clusters;
}

uint32_t lowfatfs_system_used_size(const lowfatfs* const fs_ptr) {
    return fs_ptr->_info._system_used_size;
}

int32_t lowfatfs_walk_over_changed_data(lowfatfs* fs_ptr, size_t(*procedure)(void* data, size_t size)) {
    uint32_t touched = fs_ptr->_info._clusters_touched;
    if (touched == 0) {
        return 0;
    }
    int32_t continual_range_start = LOWFATFS_NONE;
    int32_t continual_range_stop = LOWFATFS_NONE;
    int32_t cluster_next = fs_ptr->_info._last_system_cluster + 1;
    while (fs_ptr->_info._clusters_touched > fs_ptr->_info._system_used_clusters) {
        if (fs_ptr->_cluster_flags[cluster_next] & LOWFATFS_CLUSTER_TOUCHED) {
            if (continual_range_start == LOWFATFS_NONE) {
                continual_range_start = cluster_next;
                continual_range_stop = cluster_next;
            }
            else {
                continual_range_stop += 1;
            }
            fs_ptr->_info._clusters_touched--;
            fs_ptr->_cluster_flags[cluster_next] ^= LOWFATFS_CLUSTER_TOUCHED;
        }
        else {
            if (continual_range_start != LOWFATFS_NONE) {
                uint32_t cluster_size = fs_ptr->_header->_cluster_size;
                procedure((void*)(fs_ptr->_data + continual_range_start * cluster_size), (continual_range_stop - continual_range_start + 1) * cluster_size);
                continual_range_start = LOWFATFS_NONE;
                continual_range_stop = LOWFATFS_NONE;
            }
        }
        cluster_next++;
    }
    if (continual_range_start != LOWFATFS_NONE) {
        uint32_t cluster_size = fs_ptr->_header->_cluster_size;
        procedure((void*)(fs_ptr->_data + continual_range_start * cluster_size), (continual_range_stop - continual_range_start + 1) * cluster_size);
    }
    // write system clusters to the beginning, but after everything is finished
    uint32_t cluster_size = fs_ptr->_header->_cluster_size;
    fs_ptr->_info._clusters_touched -= fs_ptr->_info._system_used_clusters;
    procedure((void*)fs_ptr->_data, fs_ptr->_info._system_used_clusters * cluster_size);
    return touched;
}

int32_t lowfatfs_get_descriptor(const lowfatfs* const fs_ptr, uint32_t file_idx) {
    if (file_idx < fs_ptr->_header->_file_count) {
        int32_t cur_fd = fs_ptr->_header->_filename_table_busy_tail;
        while (file_idx) {
            cur_fd = fs_ptr->_filename_table[cur_fd].PAIR_PREV;
            file_idx--;
        }
        return cur_fd;
    }
    return LOWFATFS_NONE;
}

uint32_t lowfatfs_walk_over_all_files(const lowfatfs* const fs_ptr, void* arg, void(*procedure)(int32_t fd, void* arg)) {
    if (fs_ptr->_header->_file_count) {
        int32_t cur_fd = fs_ptr->_header->_filename_table_busy_tail;
        while (cur_fd != LOWFATFS_NONE && (uint32_t)cur_fd < fs_ptr->_header->_cluster_count && (uint32_t)cur_fd > fs_ptr->_info._last_system_cluster) {
            procedure(cur_fd, arg);
            cur_fd = fs_ptr->_filename_table[cur_fd].PAIR_PREV;
        }
    }
    return fs_ptr->_header->_file_count;
}
