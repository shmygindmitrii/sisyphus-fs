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

uint32_t lowfat_dl_calculate_range_length(const int32_t* const table_next, int32_t first, int32_t last) {
    LOWFAT_ASSERT(first >= 0 && last >= 0);
    uint32_t node_count = 1;
    while (first != last) {
        first = table_next[first];
        node_count++;
    }
    return node_count;
}

// fs

const uint64_t LOWFAT_FS_DUMP_BEGIN_MARKER = 11348751673753212928ULL;   // this is random marker of fs beginning
const uint64_t LOWFAT_FS_DUMP_END_MARKER = 907403631122679808ULL;       // this is random marker of fs ending

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
    fs_ptr->_system_used_size = 6 * sizeof(uint32_t) + 4 * sizeof(int32_t) + (sizeof(lowfat_fileprops_t) + filename_length + sizeof(int32_t) * 4) * cluster_count;
    fs_ptr->_system_used_clusters = fs_ptr->_system_used_size / cluster_size + (int)(fs_ptr->_system_used_size % cluster_size > 0);
    fs_ptr->_last_system_cluster = fs_ptr->_system_used_clusters - 1;
    LOWFAT_ASSERT(fs_ptr->_system_used_clusters < cluster_count);
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
    const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
    const uint32_t fileinfo_size = fileinfo_stride * (*fs_ptr->_cluster_count);
    fs_ptr->_filename_table_next = (int32_t*)(fs_ptr->_data + fileinfos_offset + fileinfo_size);
    fs_ptr->_filename_table_prev = fs_ptr->_filename_table_next + (*fs_ptr->_cluster_count);
    fs_ptr->_data_table_next = fs_ptr->_filename_table_prev + (*fs_ptr->_cluster_count);
    fs_ptr->_data_table_prev = fs_ptr->_data_table_next + (*fs_ptr->_cluster_count);
    fs_ptr->_filenames = fs_ptr->_data + fileinfos_offset;
    fs_ptr->_fileprops = fs_ptr->_data + fileinfos_offset + (*fs_ptr->_filename_length);
}

void lowfat_fs_reset_instance(lowfat_fs* fs_ptr) {
    *(fs_ptr->_used_memory) = fs_ptr->_system_used_size;
    *(fs_ptr->_used_cluster_count) = fs_ptr->_system_used_clusters;
    *(fs_ptr->_filename_table_busy_tail) = LF_NONE;
    *(fs_ptr->_data_table_busy_tail) = LF_NONE;
    const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
    for (uint32_t i = 0; i < *(fs_ptr->_cluster_count); i++) {
        memset(fs_ptr->_filenames + i * fileinfo_stride, 0, (*fs_ptr->_filename_length));
        lowfat_fileprops_t* props_i = (lowfat_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        RESET_LOWFAT_FILEPROPS((*props_i));
        fs_ptr->_filename_table_next[i] = i + 1;
        fs_ptr->_filename_table_prev[i] = i - 1;
        fs_ptr->_data_table_next[i] = i + 1;
        fs_ptr->_data_table_prev[i] = i - 1;
    }
    fs_ptr->_filename_table_next[*fs_ptr->_cluster_count - 1] = LF_NONE;
    *fs_ptr->_filename_table_busy_tail = fs_ptr->_last_system_cluster;
    *fs_ptr->_filename_table_free_head = fs_ptr->_last_system_cluster + 1;
    fs_ptr->_filename_table_next[*fs_ptr->_filename_table_busy_tail] = LF_NONE;
    fs_ptr->_filename_table_prev[*fs_ptr->_filename_table_free_head] = LF_NONE;

    for (uint32_t i = 0; i < fs_ptr->_system_used_clusters; i++) {
        snprintf((char*)(fs_ptr->_filenames + i * fileinfo_stride), *fs_ptr->_filename_length, "SYSTEM%d", i);
        lowfat_fileprops_t* props_i = (lowfat_fileprops_t*)(fs_ptr->_fileprops + i * fileinfo_stride);
        props_i->size = *fs_ptr->_cluster_size;
    }

    fs_ptr->_data_table_next[(*fs_ptr->_cluster_count) - 1] = LF_NONE;
    *fs_ptr->_data_table_busy_tail = fs_ptr->_last_system_cluster;
    *fs_ptr->_data_table_free_head = fs_ptr->_last_system_cluster + 1;
    fs_ptr->_data_table_next[*fs_ptr->_data_table_busy_tail] = LF_NONE;
    fs_ptr->_data_table_prev[*fs_ptr->_data_table_free_head] = LF_NONE;
}

void lowfat_fs_destroy_instance(lowfat_fs* fs_ptr) {
    LOWFAT_FS_FREE(fs_ptr);
}

int32_t lowfat_fs_open_file(lowfat_fs* fs_ptr, const char* filename, char mode) {
    if (filename == NULL) {
        return LF_ERROR_FILE_NAME_NULL;
    }
    size_t filename_len = strlen(filename);
    if (filename_len > (*(fs_ptr->_filename_length) - 1)) {
        return LF_ERROR_FILE_NAME_TOO_LONG;
    }
    int32_t fd = lowfat_fs_find_file(fs_ptr, filename);
    if (fd >= 0 && fd < (int32_t)fs_ptr->_system_used_clusters) {
        return LF_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
    if (mode == 'r') {
        if (fd >= 0) {
            CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
            fi.props->locked |= LF_FILE_READ;
        }
        return fd;
    }
    else if (mode == 'w') {
        if (fd >= 0) {
            // remove existing
            lowfat_fs_remove_file(fs_ptr, fd);
            fd = LF_ERROR_FILE_NOT_FOUND;
        }
        if (fd == LF_ERROR_FILE_ALREADY_OPENED) {
            return LF_ERROR_FILE_ALREADY_OPENED;
        }
        if (*fs_ptr->_data_table_free_head == LF_NONE) {
            return LF_ERROR_SPACE_ENDED;
        }
        LOWFAT_ASSERT(fd == LF_ERROR_FILE_NOT_FOUND);
        // LF_FILE_ERROR_NOT_FOUND - create new
        lowfat_dl_acquire_next_free(fs_ptr->_filename_table_next, fs_ptr->_filename_table_prev, fs_ptr->_filename_table_busy_tail, fs_ptr->_filename_table_free_head);
        fd = *fs_ptr->_filename_table_busy_tail;
        // put busy node to the head of list
        lowfat_dl_acquire_next_free(fs_ptr->_data_table_next, fs_ptr->_data_table_prev, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
        (*fs_ptr->_used_cluster_count)++;
        // add to _fileinfos first free first_cluster
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        sprintf_s(fi.name, *fs_ptr->_filename_length, filename);
        fi.props->mtime = 0;
        fi.props->size = 0;
        fi.props->first_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->last_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->current_cluster = *fs_ptr->_data_table_busy_tail;
        fi.props->current_byte = 0;
        fi.props->locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
        (*fs_ptr->_file_count)++;
        return fd;
    }
    return LF_ERROR_FILE_WRONG_MODE;
}

int32_t lowfat_fs_read_file(lowfat_fs* fs_ptr, uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0 && fd < (int32_t)fs_ptr->_system_used_clusters) {
        return LF_ERROR_SYSTEM_SECTION;
    }
    const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
    if (fd > (int32_t)fs_ptr->_last_system_cluster) {
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        uint32_t read_size = elem_size * count;
        if (read_size > fi.props->size) {
            return LF_ERROR_FILE_READ_SIZE_OVERFLOW;
        }
        uint32_t buf_offset = 0;
        while (read_size > 0) {
            uint32_t mem_can_read = (*fs_ptr->_cluster_size) - fi.props->current_byte;
            if (mem_can_read == 0) {
                fi.props->current_cluster = fs_ptr->_data_table_next[fi.props->current_cluster];
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
        return LF_OK;
    }
    return LF_ERROR_FILE_NOT_FOUND;
}

int32_t lowfat_fs_write_file(lowfat_fs* fs_ptr, const uint8_t* const buf, uint32_t elem_size, uint32_t count, int32_t fd) {
    if (fd >= 0) {
        // always write new
        int32_t total_write_size = elem_size * count;
        uint32_t buf_offset = 0;
        const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        while (total_write_size > 0) {
            int32_t mem_can_write = (*fs_ptr->_cluster_size) - fi.props->current_byte;
            if (mem_can_write == 0) {
                // go to the next cluster
                LOWFAT_ASSERT(*fs_ptr->_data_table_free_head != LF_NONE);
                if (*fs_ptr->_data_table_free_head == LF_NONE) {
                    return LF_ERROR_SPACE_ENDED;
                }
                lowfat_dl_acquire_next_free(fs_ptr->_data_table_next, fs_ptr->_data_table_prev, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
                fi.props->last_cluster = *fs_ptr->_data_table_busy_tail;
                fi.props->current_byte = 0;
                mem_can_write = (*fs_ptr->_cluster_size);
                (*fs_ptr->_used_cluster_count)++;
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
        const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        fi.props->locked = 0;
        fi.props->current_cluster = fi.props->first_cluster;
        fi.props->current_byte = 0;
#if LOWFAT_FS_FORBID_EMPTY_FILES
        LOWFAT_ASSERT(fi.props->size != 0);
#endif
#if _DEBUG
        printf("Close descriptor %d of size %u and crc32 = %u, remains %u\n", fd, fi.props->size, fi.props->crc32, lowfat_fs_free_available_mem_size(fs_ptr));
#endif
        return LF_OK;
    }
    return fd;
}

uint32_t lowfat_fs_remove_file(lowfat_fs* fs_ptr, int fd) {
    LOWFAT_ASSERT(fd >= 0 && fd < (int32_t)*fs_ptr->_cluster_count);
    if (fd >= 0 && fd < (int32_t)*fs_ptr->_cluster_count) {
        // busy clusters handle
        const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        int32_t first_cluster = fi.props->first_cluster;
        int32_t last_cluster = fi.props->last_cluster;
        uint32_t freed_clusters = lowfat_dl_calculate_range_length(fs_ptr->_data_table_next, first_cluster, last_cluster);
        (*fs_ptr->_used_cluster_count) -= freed_clusters;
        lowfat_dl_free_busy_range(fs_ptr->_data_table_next, fs_ptr->_data_table_prev, first_cluster, last_cluster, fs_ptr->_data_table_busy_tail, fs_ptr->_data_table_free_head);
        // 
        lowfat_dl_free_busy_range(fs_ptr->_filename_table_next, fs_ptr->_filename_table_prev, fd, fd, fs_ptr->_filename_table_busy_tail, fs_ptr->_filename_table_free_head);
        // reset properties
        (*fs_ptr->_used_memory) -= fi.props->size;
#if _DEBUG
        printf("Remove file '%s' of size %u\n", fi.name, fi.props->size);
#endif
        memset(fi.name, 0, *fs_ptr->_filename_length);
        RESET_LOWFAT_FILEPROPS((*fi.props));
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
    if (fd >= LF_OK) {
        return lowfat_fs_remove_file(fs_ptr, fd);
    }
    return fd;
}

int32_t lowfat_fs_find_file(lowfat_fs* fs_ptr, const char* filename) {
    // linear search
    int32_t busy_head = fs_ptr->_filename_table_next[fs_ptr->_last_system_cluster];
    const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
    while (busy_head != LF_NONE) {
        if (strcmp((char*)(fs_ptr->_filenames + busy_head * fileinfo_stride), filename) == 0) {
            return busy_head;
        }
        busy_head = fs_ptr->_filename_table_next[busy_head];
    }
    return LF_ERROR_FILE_NOT_FOUND;
}

lowfat_fileinfo_t lowfat_fs_file_stat(lowfat_fs* fs_ptr, int32_t fd) {
    LOWFAT_ASSERT(fd >= 0 && fd < (int32_t)(*fs_ptr->_cluster_count));
    if (fd >= 0 && fd < (int32_t)(*fs_ptr->_cluster_count)) {
        const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    else {
        CREATE_LOWFAT_FILEINFO(empty, NULL, NULL);
        return empty;
    }
}

uint32_t lowfat_fs_free_mem_size(const lowfat_fs* const fs_ptr) {
    // real free space, that includes unused clusters memory
    return fs_ptr->_total_size - (*fs_ptr->_used_memory);
}

lowfat_fileinfo_t lowfat_fs_file_stat_str(lowfat_fs* fs_ptr, const char* name) {
    int fd = lowfat_fs_find_file(fs_ptr, name);
    if (fd != LF_ERROR_FILE_NOT_FOUND) {
        const uint32_t fileinfo_stride = sizeof(lowfat_fileprops_t) + (*fs_ptr->_filename_length);
        CREATE_LOWFAT_FILEINFO(fi, fs_ptr->_filenames + fd * fileinfo_stride, fs_ptr->_fileprops + fd * fileinfo_stride);
        return fi;
    }
    CREATE_LOWFAT_FILEINFO(empty, NULL, NULL);
    return empty;
}

uint32_t lowfat_fs_free_available_mem_size(lowfat_fs* fs_ptr) {
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
