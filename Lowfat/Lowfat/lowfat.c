#include "lowfat_prelude.h"
#include "lowfat_defines.h"
#include "lowfat.h"

#ifdef LOWFAT_FS_CUSTOM_ALLOCATOR
extern void* user_malloc(size_t size);
extern void user_free(void*);
#define LOWFAT_FS_ALLOC user_malloc
#define LOWFAT_FS_FREE user_free
#else
#pragma message("Warning: use default malloc and free")
#define LOWFAT_FS_ALLOC malloc
#define LOWFAT_FS_FREE free
#endif

// double linked-list functions
#define PAIR_NEXT second
#define PAIR_PREV first
// tail addition
void lowfat_fs_dl_acquire_next_free(structures_int_pair_t* table, int32_t* last_busy, int32_t* first_free) {
    int32_t cur_free = *first_free;
    LOWFAT_FS_ASSERT(table[cur_free].PAIR_PREV == LOWFAT_FS_NONE);
    *first_free = table[*first_free].PAIR_NEXT;
    if (*first_free != LOWFAT_FS_NONE) {
        table[*first_free].PAIR_PREV = LOWFAT_FS_NONE;
    }
    LOWFAT_FS_ASSERT(table[*last_busy].PAIR_NEXT == LOWFAT_FS_NONE);
    table[cur_free].PAIR_PREV = *last_busy;
    table[*last_busy].PAIR_NEXT = cur_free;
    table[cur_free].PAIR_NEXT = LOWFAT_FS_NONE;
    *last_busy = cur_free;
}

void lowfat_fs_dl_free_busy_range(structures_int_pair_t* table, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free) {
    // merge busy list segments
    int32_t prev = table[first].PAIR_PREV;
    int32_t next = table[last].PAIR_NEXT;
    table[prev].PAIR_NEXT = next; // never LOWFAT_FS_NONE, because of system used nodes
    if (next != LOWFAT_FS_NONE) {
        table[next].PAIR_PREV = prev;
    }
    else {
        *last_busy = prev;
    }
    // detach from busy chain and attach to free one in the beginning
    table[first].PAIR_PREV = LOWFAT_FS_NONE;
    table[last].PAIR_NEXT = *first_free;
    if (*first_free != LOWFAT_FS_NONE) {
        LOWFAT_FS_ASSERT(table[*first_free].PAIR_PREV == LOWFAT_FS_NONE);
        table[*first_free].PAIR_PREV = last;
    }
    *first_free = first;
}

uint32_t lowfat_fs_dl_calculate_range_length(const structures_int_pair_t* const table, int32_t first, int32_t last) {
    LOWFAT_FS_ASSERT(first >= 0 && last >= 0);
    uint32_t node_count = 1;
    while (first != last) {
        first = table[first].PAIR_NEXT;
        node_count++;
    }
    return node_count;
}

// fileprops 

void lowfat_fs_reset_fileprops(lowfat_fs_fileprops_t* props) {
    props->mtime = 0; 
    props->size = 0;
    props->crc32 = CRC32_CCIT_DEFAULT_VALUE;
    props->first_cluster = LOWFAT_FS_NONE;
    props->last_cluster = LOWFAT_FS_NONE;
    props->current_cluster = LOWFAT_FS_NONE;
    props->current_byte = 0;
    props->locked = 0;
}

// fileinfo

lowfat_fs_fileinfo_t lowfat_fs_create_fileinfo(void* name_ptr, void* props_ptr) {
    lowfat_fs_fileinfo_t finfo;
    finfo.name = (char*)(name_ptr);
    finfo.props = (lowfat_fs_fileprops_t*)(props_ptr);
    return finfo;
}

// fs

lowfat_fs* lowfat_fs_create_instance(uint32_t cluster_size, uint32_t cluster_count, uint32_t filename_length, uint8_t* mem) {
    lowfat_fs* fs_ptr = (lowfat_fs*)LOWFAT_FS_ALLOC(sizeof(lowfat_fs));
    fs_ptr->_data = mem;
    fs_ptr->_total_size = cluster_count * cluster_size;
    fs_ptr->_cluster_size = (uint32_t*)fs_ptr->_data;
    fs_ptr->_cluster_count = fs_ptr->_cluster_size + 1;
    fs_ptr->_filename_length = fs_ptr->_cluster_size + 2;
    *(fs_ptr->_cluster_size) = cluster_size;
    *(fs_ptr->_cluster_count) = cluster_count;
    *(fs_ptr->_filename_length) = filename_length;
    fs_ptr->_system_used_size = 6 * sizeof(uint32_t) + 4 * sizeof(int32_t) + (sizeof(lowfat_fs_fileprops_t) + filename_length + sizeof(int32_t) * 4 + sizeof(uint16_t)) * cluster_count;
    fs_ptr->_system_used_clusters = fs_ptr->_system_used_size / cluster_size + (fs_ptr->_system_used_size % cluster_size > 0);
    fs_ptr->_last_system_cluster = fs_ptr->_system_used_clusters - 1;
    fs_ptr->_clusters_touched = 0;
    LOWFAT_FS_ASSERT(fs_ptr->_system_used_clusters < cluster_count);
    return fs_ptr;
}

void lowfat_fs_set_instance_addresses(lowfat_fs* fs_ptr) {
    fs_ptr->_used_memory = fs_ptr->_cluster_size + 3;
    fs_ptr->_used_cluster_count = fs_ptr->_cluster_size + 4;
    fs_ptr->_file_count = fs_ptr->_cluster_size + 5;
    fs_ptr->_filename_table_busy_tail = (int32_t*)fs_ptr->_file_count + 1;
    fs_ptr->_filename_table_free_head = fs_ptr->_filename_table_busy_tail + 1;
    fs_ptr->_data_table_busy_tail = fs_ptr->_filename_table_busy_tail + 2;
    fs_ptr->_data_table_free_head = fs_ptr->_filename_table_busy_tail + 3;
    // 40 bytes used for common fs values
    const uint32_t fileinfos_offset = 40;
    const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
    const uint32_t fileinfo_size = fileinfo_stride * (*fs_ptr->_cluster_count);
    fs_ptr->_filenames = fs_ptr->_data + fileinfos_offset;
    fs_ptr->_fileprops = fs_ptr->_data + fileinfos_offset + (*fs_ptr->_filename_length);
    fs_ptr->_filename_table = (structures_int_pair_t*)(fs_ptr->_data + fileinfos_offset + fileinfo_size);
    fs_ptr->_data_table = fs_ptr->_filename_table + (*fs_ptr->_cluster_count);
    fs_ptr->_cluster_flags = (uint16_t*)(fs_ptr->_data_table + (*fs_ptr->_cluster_count));
}

void lowfat_fs_reset_instance(lowfat_fs* fs_ptr) {
    *(fs_ptr->_used_memory) = fs_ptr->_system_used_size;
    *(fs_ptr->_used_cluster_count) = fs_ptr->_system_used_clusters;
    *(fs_ptr->_filename_table_busy_tail) = LOWFAT_FS_NONE;
    *(fs_ptr->_data_table_busy_tail) = LOWFAT_FS_NONE;
    const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
    for (uint32_t i = 0; i < *(fs_ptr->_cluster_count); i++) {
        memset(fs_ptr->_filenames + i * fileinfo_stride, 0, (*fs_ptr->_filename_length));
        lowfat_fs_fileprops_t* props_i = (lowfat_fs_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        lowfat_fs_reset_fileprops(props_i);
        fs_ptr->_filename_table[i].PAIR_NEXT = i + 1;
        fs_ptr->_filename_table[i].PAIR_PREV = i - 1;
        fs_ptr->_data_table[i].PAIR_NEXT = i + 1;
        fs_ptr->_data_table[i].PAIR_PREV = i - 1;
        fs_ptr->_cluster_flags[i] = 0;
    }
    fs_ptr->_filename_table[*fs_ptr->_cluster_count - 1].PAIR_NEXT = LOWFAT_FS_NONE;
    *fs_ptr->_filename_table_busy_tail = fs_ptr->_last_system_cluster;
    *fs_ptr->_filename_table_free_head = fs_ptr->_last_system_cluster + 1;
    fs_ptr->_filename_table[*fs_ptr->_filename_table_busy_tail].PAIR_NEXT = LOWFAT_FS_NONE;
    fs_ptr->_filename_table[*fs_ptr->_filename_table_free_head].PAIR_PREV = LOWFAT_FS_NONE;

    for (uint32_t i = 0; i < fs_ptr->_system_used_clusters; i++) {
        snprintf((char*)(fs_ptr->_filenames + i * fileinfo_stride), *fs_ptr->_filename_length, "SYSTEM%d", i);
        lowfat_fs_fileprops_t* props_i = (lowfat_fs_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        props_i->size = *fs_ptr->_cluster_size;
    }

    fs_ptr->_data_table[(*fs_ptr->_cluster_count) - 1].PAIR_NEXT = LOWFAT_FS_NONE;
    *fs_ptr->_data_table_busy_tail = fs_ptr->_last_system_cluster;
    *fs_ptr->_data_table_free_head = fs_ptr->_last_system_cluster + 1;
    fs_ptr->_data_table[*fs_ptr->_data_table_busy_tail].PAIR_NEXT = LOWFAT_FS_NONE;
    fs_ptr->_data_table[*fs_ptr->_data_table_free_head].PAIR_PREV = LOWFAT_FS_NONE;
}

void lowfat_fs_destroy_instance(lowfat_fs* fs_ptr) {
    LOWFAT_FS_FREE(fs_ptr);
}

static inline void lowfat_fs_increment_touched_clusters_count(lowfat_fs* fs_ptr, uint32_t clusters) {
    if (fs_ptr->_clusters_touched == 0) {
        fs_ptr->_clusters_touched += fs_ptr->_system_used_clusters;
    }
    fs_ptr->_clusters_touched += clusters;
}

int32_t lowfat_fs_open_file(lowfat_fs* fs_ptr, const char* filename, char mode) {
    if (filename == NULL) {
        return LOWFAT_FS_ERROR_FILE_NAME_NULL;
    }
    size_t filename_len = strlen(filename);
    if (filename_len > (*(fs_ptr->_filename_length) - 1)) {
        return LOWFAT_FS_ERROR_FILE_NAME_TOO_LONG;
    }
    int32_t fd = lowfat_fs_find_file(fs_ptr, filename);
    if (fd >= 0 && fd < (int32_t)fs_ptr->_system_used_clusters) {
        return LOWFAT_FS_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
    if (mode == 'r') {
        if (fd >= 0) {
            lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
            fi.props->locked |= LOWFAT_FS_FILE_READ;
        }
        return fd;
    }
    else if (mode == 'w') {
        if (fd >= 0) {
            // remove existing
            lowfat_fs_remove_file(fs_ptr, fd);
            fd = LOWFAT_FS_ERROR_FILE_NOT_FOUND;
        }
        if (fd == LOWFAT_FS_ERROR_FILE_ALREADY_OPENED) {
            return LOWFAT_FS_ERROR_FILE_ALREADY_OPENED;
        }
        if (*fs_ptr->_data_table_free_head == LOWFAT_FS_NONE) {
            return LOWFAT_FS_ERROR_SPACE_ENDED;
        }
        LOWFAT_FS_ASSERT(fd == LOWFAT_FS_ERROR_FILE_NOT_FOUND);
        // LOWFAT_FS_FILE_ERROR_NOT_FOUND - create new
        lowfat_fs_dl_acquire_next_free(fs_ptr->_filename_table, fs_ptr->_filename_table_busy_tail, fs_ptr->_filename_table_free_head);
        fd = *fs_ptr->_filename_table_busy_tail;
        // put busy node to the head of list
        lowfat_fs_dl_acquire_next_free(fs_ptr->_data_table, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
        (*fs_ptr->_used_cluster_count)++;
        // add to _fileinfos first free first_cluster
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        sprintf_s(fi.name, *fs_ptr->_filename_length, filename);
        fi.props->mtime = 0;
        fi.props->size = 0;
        fi.props->first_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->last_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->current_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->current_byte = 0;
        fi.props->locked = (LOWFAT_FS_FILE_LOCKED | LOWFAT_FS_FILE_WRITE);
        fs_ptr->_cluster_flags[fi.props->last_cluster] |= LOWFAT_FS_CLUSTER_TOUCHED;
#if LOWFAT_FS_VERBOSITY == LOWFAT_FS_VERBOSITY_MAX
        printf("OPEN[%d]: touched cluster %d \n", *fs_ptr->_file_count, fi.props->last_cluster);
#endif
        (*fs_ptr->_file_count)++;
        lowfat_fs_increment_touched_clusters_count(fs_ptr, 1);
        return fd;
    }
    return LOWFAT_FS_ERROR_FILE_WRONG_MODE;
}

int32_t lowfat_fs_read_file(lowfat_fs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0 && fd < (int32_t)fs_ptr->_system_used_clusters) {
        return LOWFAT_FS_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
    if (fd > (int32_t)fs_ptr->_last_system_cluster) {
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        uint32_t read_size = elem_size * count;
        if (read_size > fi.props->size) {
            return LOWFAT_FS_ERROR_FILE_READ_SIZE_OVERFLOW;
        }
        uint32_t buf_offset = 0;
        while (read_size > 0) {
            uint32_t mem_can_read = (*fs_ptr->_cluster_size) - fi.props->current_byte;
            if (mem_can_read == 0) {
                fi.props->current_cluster = fs_ptr->_data_table[fi.props->current_cluster].PAIR_NEXT;
                fi.props->current_byte = 0;
                mem_can_read = (*fs_ptr->_cluster_size);
            }
            if (mem_can_read > read_size) {
                mem_can_read = read_size;
            }
            //
            uint32_t offset = fi.props->current_cluster * (*fs_ptr->_cluster_size) + fi.props->current_byte;
            memcpy(buf + buf_offset, &fs_ptr->_data[offset], mem_can_read);
            //
            fi.props->current_byte += (uint16_t)mem_can_read;
            buf_offset += mem_can_read;
            read_size -= mem_can_read;
        }
        return LOWFAT_FS_OK;
    }
    return LOWFAT_FS_ERROR_FILE_NOT_FOUND;
}

int32_t lowfat_fs_write_file(lowfat_fs* fs_ptr, const uint8_t* const buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0) {
        // always write new
        int32_t total_write_size = elem_size * count;
        uint32_t buf_offset = 0;
        const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        const uint32_t prev_used_clusters = *fs_ptr->_used_cluster_count;
        while (total_write_size > 0) {
            int32_t mem_can_write = (*fs_ptr->_cluster_size) - fi.props->current_byte;
            if (mem_can_write == 0) {
                // go to the next cluster
                LOWFAT_FS_ASSERT(*fs_ptr->_data_table_free_head != LOWFAT_FS_NONE);
                if (*fs_ptr->_data_table_free_head == LOWFAT_FS_NONE) {
                    return LOWFAT_FS_ERROR_SPACE_ENDED;
                }
                lowfat_fs_dl_acquire_next_free(fs_ptr->_data_table, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
                fi.props->last_cluster = *fs_ptr->_data_table_busy_tail;
                fi.props->current_byte = 0;
                mem_can_write = (*fs_ptr->_cluster_size);
                (*fs_ptr->_used_cluster_count)++;
                fs_ptr->_cluster_flags[fi.props->last_cluster] |= LOWFAT_FS_CLUSTER_TOUCHED;
#if LOWFAT_FS_VERBOSITY == LOWFAT_FS_VERBOSITY_MAX
                printf("WRITE[%d]: touched cluster %d \n", fd, fi.props->last_cluster);
#endif
            }
            if (mem_can_write >= total_write_size) {
                mem_can_write = total_write_size;
            }
            uint32_t offset = fi.props->last_cluster * (*fs_ptr->_cluster_size) + fi.props->current_byte;
            //
            memcpy(fs_ptr->_data + offset, buf + buf_offset, mem_can_write);
            //
            fi.props->current_byte += (uint16_t)mem_can_write;
            fi.props->size += mem_can_write;
            buf_offset += mem_can_write;
            total_write_size -= mem_can_write;
        }
        fi.props->crc32 = crc32_ccit_update(buf, elem_size * count, fi.props->crc32);
        (*fs_ptr->_used_memory) += elem_size * count;
        lowfat_fs_increment_touched_clusters_count(fs_ptr, (*fs_ptr->_used_cluster_count) - prev_used_clusters);
        return count;
    }
    else {
#if _DEBUG
        __debugbreak();
#endif
        return -1;
    }
}

int32_t lowfat_fs_close_file(lowfat_fs* fs_ptr, int32_t fd) {
    if (fd >= 0) {
        const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        fi.props->current_cluster = fi.props->first_cluster;
        fi.props->current_byte = 0;
#if LOWFAT_FS_FORBID_EMPTY_FILES
        LOWFAT_FS_ASSERT(fi.props->size != 0);
#endif
#if LOWFAT_FS_VERBOSITY == LOWFAT_FS_VERBOSITY_DETAILED
        if (fi.props->locked & LOWFAT_FS_FILE_WRITE) {
            printf("Close descriptor %d of size %u and crc32 = %u, space remains = %u bytes\n", fd, fi.props->size, fi.props->crc32, lowfat_fs_free_available_mem_size(fs_ptr));
        }
        else {
            printf("Close descriptor %d of size %u and crc32 = %u\n", fd, fi.props->size, fi.props->crc32);
        }
#endif
        fi.props->locked &= LOWFAT_FS_FILE_LRW_INV_MASK;
        return LOWFAT_FS_OK;
    }
    return fd;
}

uint32_t lowfat_fs_remove_file(lowfat_fs* fs_ptr, int32_t fd) {
    LOWFAT_FS_ASSERT(fd >= 0 && fd < (int32_t)*fs_ptr->_cluster_count);
    if (fd >= 0 && fd < (int32_t)*fs_ptr->_cluster_count) {
        // busy clusters handle
        const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        int32_t first_cluster = fi.props->first_cluster;
        int32_t last_cluster = fi.props->last_cluster;
        uint32_t freed_clusters = lowfat_fs_dl_calculate_range_length(fs_ptr->_data_table, first_cluster, last_cluster);
        (*fs_ptr->_used_cluster_count) -= freed_clusters;
        lowfat_fs_dl_free_busy_range(fs_ptr->_data_table, first_cluster, last_cluster, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
        // 
        lowfat_fs_dl_free_busy_range(fs_ptr->_filename_table, fd, fd, fs_ptr->_filename_table_busy_tail, fs_ptr->_filename_table_free_head);
        // reset properties
        (*fs_ptr->_used_memory) -= fi.props->size;
#if LOWFAT_FS_VERBOSITY == LOWFAT_FS_VERBOSITY_DETAILED
        printf("Remove file '%s' of size %u\n", fi.name, fi.props->size);
#endif
        memset(fi.name, 0, *fs_ptr->_filename_length);
        lowfat_fs_reset_fileprops(fi.props);
        (*fs_ptr->_file_count)--;
        lowfat_fs_increment_touched_clusters_count(fs_ptr, 0); // add _system_used_clusters if not added already
        return freed_clusters;
    }
    else {
        return 0;
    }
}

int32_t lowfat_fs_remove_file_str(lowfat_fs* fs_ptr, const char* filename) {
    int32_t fd = lowfat_fs_find_file(fs_ptr, filename);
    if (fd >= LOWFAT_FS_OK) {
        return lowfat_fs_remove_file(fs_ptr, fd);
    }
    return fd;
}

int32_t lowfat_fs_find_file(lowfat_fs* fs_ptr, const char* filename) {
    // linear search
    int32_t busy_head = fs_ptr->_filename_table[fs_ptr->_last_system_cluster].PAIR_NEXT;
    const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
    while (busy_head != LOWFAT_FS_NONE) {
        if (strcmp((char*)(fs_ptr->_filenames + busy_head * fileinfo_stride), filename) == 0) {
            return busy_head;
        }
        busy_head = fs_ptr->_filename_table[busy_head].PAIR_NEXT;
    }
    return LOWFAT_FS_ERROR_FILE_NOT_FOUND;
}

lowfat_fs_fileinfo_t lowfat_fs_file_stat(lowfat_fs* fs_ptr, int32_t fd) {
    LOWFAT_FS_ASSERT(fd >= 0 && fd < (int32_t)(*fs_ptr->_cluster_count));
    if (fd >= 0 && fd < (int32_t)(*fs_ptr->_cluster_count)) {
        const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    else {
        lowfat_fs_fileinfo_t empty = lowfat_fs_create_fileinfo(NULL, NULL);
        return empty;
    }
}

uint32_t lowfat_fs_free_mem_size(const lowfat_fs* const fs_ptr) {
    // real free space, that includes unused clusters memory
    return fs_ptr->_total_size - (*fs_ptr->_used_memory);
}

lowfat_fs_fileinfo_t lowfat_fs_file_stat_str(lowfat_fs* fs_ptr, const char* name) {
    int fd = lowfat_fs_find_file(fs_ptr, name);
    if (fd != LOWFAT_FS_ERROR_FILE_NOT_FOUND) {
        const uint32_t fileinfo_stride = sizeof(lowfat_fs_fileprops_t) + (*fs_ptr->_filename_length);
        lowfat_fs_fileinfo_t fi = lowfat_fs_create_fileinfo(fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    lowfat_fs_fileinfo_t empty = lowfat_fs_create_fileinfo(NULL, NULL);
    return empty;
}

uint32_t lowfat_fs_free_available_mem_size(const lowfat_fs* const fs_ptr) {
    // real writable amount of memory
    return (*fs_ptr->_cluster_count - *fs_ptr->_used_cluster_count) * (*fs_ptr->_cluster_size);
}

uint32_t lowfat_fs_file_count(const lowfat_fs* const fs_ptr) {
    return *fs_ptr->_file_count;
}

uint32_t lowfat_fs_filename_length(const lowfat_fs* const fs_ptr) {
    return *fs_ptr->_filename_length;
}

uint32_t lowfat_fs_cluster_size(const lowfat_fs* const fs_ptr) {
    return *fs_ptr->_cluster_size;
}

uint32_t lowfat_fs_cluster_count(const lowfat_fs* const fs_ptr) {
    return *fs_ptr->_cluster_count;
}

uint32_t lowfat_fs_total_size(const lowfat_fs* const fs_ptr) {
    return (*fs_ptr->_cluster_count) * (*fs_ptr->_cluster_size);
}

uint32_t lowfat_fs_system_used_clusters(const lowfat_fs* const fs_ptr) {
    return fs_ptr->_system_used_clusters;
}

uint32_t lowfat_fs_system_used_size(const lowfat_fs* const fs_ptr) {
    return fs_ptr->_system_used_size;
}

int32_t lowfat_fs_walk_over_changed_data(lowfat_fs* fs_ptr, size_t(*procedure)(void* data, size_t size)) {
    uint32_t touched = fs_ptr->_clusters_touched;
    if (touched == 0) {
        return 0;
    }
    int32_t continual_range_start = LOWFAT_FS_NONE;
    int32_t continual_range_stop = LOWFAT_FS_NONE;
    int32_t cluster_next = fs_ptr->_last_system_cluster + 1;
    while (fs_ptr->_clusters_touched > fs_ptr->_system_used_clusters) {
        if (fs_ptr->_cluster_flags[cluster_next] & LOWFAT_FS_CLUSTER_TOUCHED) {
            if (continual_range_start == LOWFAT_FS_NONE) {
                continual_range_start = cluster_next;
                continual_range_stop = cluster_next;
            }
            else {
                continual_range_stop += 1;
            }
            fs_ptr->_clusters_touched--;
            fs_ptr->_cluster_flags[cluster_next] ^= LOWFAT_FS_CLUSTER_TOUCHED;
        }
        else {
            if (continual_range_start != LOWFAT_FS_NONE) {
                uint32_t cluster_size = *fs_ptr->_cluster_size;
                procedure((void*)(fs_ptr->_data + continual_range_start * cluster_size), (continual_range_stop - continual_range_start + 1) * cluster_size);
                continual_range_start = LOWFAT_FS_NONE;
                continual_range_stop = LOWFAT_FS_NONE;
            }
        }
        cluster_next++;
    }
    if (continual_range_start != LOWFAT_FS_NONE) {
        uint32_t cluster_size = *fs_ptr->_cluster_size;
        procedure((void*)(fs_ptr->_data + continual_range_start * cluster_size), (continual_range_stop - continual_range_start + 1) * cluster_size);
    }
    // write system clusters to the beginning, but after everything is finished
    uint32_t cluster_size = *fs_ptr->_cluster_size;
    fs_ptr->_clusters_touched -= fs_ptr->_system_used_clusters;
    procedure((void*)fs_ptr->_data, fs_ptr->_system_used_clusters * cluster_size);
    return touched;
}

int32_t lowfat_fs_get_descriptor(const lowfat_fs* const fs_ptr, uint32_t file_idx) {
    if (file_idx < *fs_ptr->_file_count) {
        int32_t cur_fd = *fs_ptr->_filename_table_busy_tail;
        while (file_idx) {
            cur_fd = fs_ptr->_filename_table[cur_fd].PAIR_PREV;
            file_idx--;
        }
        return cur_fd;
    }
    return LOWFAT_FS_NONE;
}

uint32_t lowfat_fs_walk_over_all_files(const lowfat_fs* const fs_ptr, void* arg, void(*procedure)(int32_t fd, void* arg)) {
    if (*fs_ptr->_file_count) {
        int32_t cur_fd = *fs_ptr->_filename_table_busy_tail;
        while (cur_fd != LOWFAT_FS_NONE && (uint32_t)cur_fd < *fs_ptr->_cluster_count && (uint32_t)cur_fd > fs_ptr->_last_system_cluster) {
            procedure(cur_fd, arg);
            cur_fd = fs_ptr->_filename_table[cur_fd].PAIR_PREV;
        }
    }
    return *fs_ptr->_file_count;
}
