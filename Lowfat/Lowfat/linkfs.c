#include "linkfs_prelude.h"
#include "linkfs_defines.h"
#include "linkfs.h"

#ifdef LINKFS_CUSTOM_ALLOCATOR
extern void* user_malloc(size_t size);
extern void user_free(void*);
#define LINKFS_ALLOC user_malloc
#define LINKFS_FREE user_free
#else
#pragma message("[ linkfs ] warning: use default malloc and free")
#define LINKFS_ALLOC malloc
#define LINKFS_FREE free
#endif

#define LINKFS_PRINT_ERROR "[ linkfs ][ error ]: "
#define LINKFS_PRINT_WARNING "[ linkfs ][ warning ]: "
#define LINKFS_PRINT_INFO "[ linkfs ][ info ]: "

void default_debugbreak(const char* const format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
    __debugbreak();
}

#ifdef LINKFS_CUSTOM_DEBUGBREAK
extern void user_debugbreak(const char* const format, ...);
#define LINKFS_DEBUGBREAK user_debugbreak
#else
#define LINKFS_DEBUGBREAK default_debugbreak
#endif

linkfs_string_t* linkfs_create_string(const char* line) {
    size_t len = strlen(line) + 1;
    linkfs_string_t* str_ptr = LINKFS_ALLOC(sizeof(linkfs_string_t));
    str_ptr->length = len;
    str_ptr->content = LINKFS_ALLOC(len);
    str_ptr->content[len - 1] = '\0';
    memcpy(str_ptr->content, line, len);
    return str_ptr;
}

void linkfs_destroy_string(linkfs_string_t* str_ptr) {
    if (str_ptr) {
        LINKFS_FREE(str_ptr->content);
        LINKFS_FREE(str_ptr);
    }
}

linkfs_memory_block_t* linkfs_create_memory_block(size_t size) {
    linkfs_memory_block_t* block_ptr = LINKFS_ALLOC(sizeof(linkfs_memory_block_t));
    block_ptr->size = size;
    block_ptr->data = LINKFS_ALLOC(size);
    return block_ptr;
}

void linkfs_destroy_memory_block(linkfs_memory_block_t* block_ptr) {
    if (block_ptr) {
        LINKFS_FREE(block_ptr->data);
        LINKFS_FREE(block_ptr);
    }
}

linkfs_cluster_t* linkfs_create_cluster(size_t block_size) {
    linkfs_cluster_t* cluster_ptr = LINKFS_ALLOC(sizeof(linkfs_cluster_t));
    cluster_ptr->block = linkfs_create_memory_block(block_size);
    cluster_ptr->next = NULL;
    return cluster_ptr;
}

void linkfs_destroy_cluster(linkfs_cluster_t* cluster_ptr) {
    if (cluster_ptr) {
        linkfs_destroy_memory_block(cluster_ptr->block);
        LINKFS_FREE(cluster_ptr);
    }
}

void linkfs_set_default_file(linkfs_file_t* file_ptr, size_t block_size) {
    file_ptr->block_size = block_size;
    file_ptr->block_count = 1;
    file_ptr->size = 0;
    file_ptr->crc = 0;
    file_ptr->start = linkfs_create_cluster(block_size);
    file_ptr->current = file_ptr->start;
    file_ptr->current_index = 0;
    file_ptr->current_byte = 0;
    file_ptr->flags = 0;
}

linkfs_file_t* linkfs_create_file(const char* filename, size_t block_size) {
    linkfs_file_t* file_ptr = LINKFS_ALLOC(sizeof(linkfs_file_t));
    file_ptr->filename = linkfs_create_string(filename);
    linkfs_set_default_file(file_ptr, block_size);
    return file_ptr;
}

linkfs_cluster_t* linkfs_file_append_cluster(linkfs_file_t* file_ptr) {
    if (file_ptr) {
        file_ptr->current->next = linkfs_create_cluster(file_ptr->block_size);
        file_ptr->current = file_ptr->current->next;
        file_ptr->current_index++;
        file_ptr->block_count++;
        file_ptr->current_byte = 0;
        file_ptr->size += file_ptr->block_size;
        return file_ptr->current;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

void linkfs_destroy_file(linkfs_file_t* file_ptr) {
    if (file_ptr) {
        linkfs_destroy_string(file_ptr->filename);
        // current block does not hold anything, just refer
        linkfs_cluster_t* current_cluster = file_ptr->start;
        while (current_cluster) {
            linkfs_cluster_t* next_cluster = current_cluster->next;
            linkfs_destroy_cluster(current_cluster);
            current_cluster = next_cluster;
        }
        file_ptr->filename = NULL;
        file_ptr->block_size = 0;
        file_ptr->block_count = 0;
        file_ptr->size = 0;
        file_ptr->crc = 0;
        file_ptr->start = NULL;
        file_ptr->current = NULL;
        file_ptr->current_index = 0;
        file_ptr->current_byte = 0;
        file_ptr->flags = 0;
        LINKFS_FREE(file_ptr);
    }
}

linkfs_file_vector_t* linkfs_create_file_vector() {
    linkfs_file_vector_t* file_vector_ptr = LINKFS_ALLOC(sizeof(linkfs_file_vector_t));
    file_vector_ptr->capacity = 0;
    file_vector_ptr->size = 0;
    file_vector_ptr->entries = NULL;
    return file_vector_ptr;
}

linkfs_file_t* linkfs_file_vector_find(const linkfs_file_vector_t* const file_vector_ptr, const char* filename) {
    if (file_vector_ptr) {
        for (size_t i = 0; i < file_vector_ptr->size; i++) {
            if (strcmp(filename, file_vector_ptr->entries[i]->filename->content) == 0) {
                return file_vector_ptr->entries[i];
            }
        }
    }
    return NULL;
}

linkfs_file_t* linkfs_file_vector_append_new(linkfs_file_vector_t* file_vector_ptr, const char* filename, size_t block_size) {
    if (file_vector_ptr) {
        linkfs_file_t* file_ptr = linkfs_create_file(filename, block_size);
        if (file_vector_ptr->size == file_vector_ptr->capacity) {
            // place finished
            size_t new_capacity = file_vector_ptr->capacity ? file_vector_ptr->capacity * 2 : 8ULL;
            linkfs_file_t** files = LINKFS_ALLOC(new_capacity * sizeof(linkfs_file_t*));
            if (file_vector_ptr->capacity > 0) {
                memcpy(files, file_vector_ptr->entries, file_vector_ptr->capacity * sizeof(linkfs_file_t*));
                LINKFS_FREE(file_vector_ptr->entries);
            }
            file_vector_ptr->entries = files;
            file_vector_ptr->capacity = new_capacity;
        }
        file_vector_ptr->entries[file_vector_ptr->size++] = file_ptr;
        return file_ptr;
    }
    return NULL;
}

int32_t linkfs_file_vector_remove(linkfs_file_vector_t* file_vector_ptr, linkfs_file_t* file_ptr) {
    if (file_vector_ptr) {
        for (size_t i = 0; i < file_vector_ptr->size; i++) {
            if (file_ptr == file_vector_ptr->entries[i]) {
                linkfs_destroy_file(file_vector_ptr->entries[i]);
                if (i != file_vector_ptr->size - 1) {
                    file_vector_ptr->entries[i] = file_vector_ptr->entries[file_vector_ptr->size - 1];
                    file_vector_ptr->entries[file_vector_ptr->size - 1] = NULL;
                }
                file_vector_ptr->size--;
                return 0;
            }
        }
    }
    return -1;
}

int32_t linkfs_file_vector_remove_str(linkfs_file_vector_t* file_vector_ptr, const char* filename) {
    if (file_vector_ptr) {
        for (size_t i = 0; i < file_vector_ptr->size; i++) {
            if (strcmp(filename, file_vector_ptr->entries[i]->filename->content) == 0) {
                linkfs_destroy_file(file_vector_ptr->entries[i]);
                if (i != file_vector_ptr->size - 1) {
                    file_vector_ptr->entries[i] = file_vector_ptr->entries[file_vector_ptr->size - 1];
                    file_vector_ptr->entries[file_vector_ptr->size - 1] = NULL;
                }
                file_vector_ptr->size--;
                return 0;
            }
        }
    }
    return -1;
}

void linkfs_destroy_file_vector(linkfs_file_vector_t* file_vector_ptr) {
    if (file_vector_ptr) {
        for (size_t i = 0; i < file_vector_ptr->size; i++) {
            linkfs_destroy_file(file_vector_ptr->entries[i]);
        }
        file_vector_ptr->capacity = 0;
        file_vector_ptr->size = 0;
        if (file_vector_ptr->entries) {
            LINKFS_FREE(file_vector_ptr->entries);
        }
        LINKFS_FREE(file_vector_ptr);
    }
}

linkfs* linkfs_create_instance() {
    linkfs* fs_ptr = LINKFS_ALLOC(sizeof(linkfs));
    fs_ptr->files = linkfs_create_file_vector();
    return fs_ptr;
}

void linkfs_destroy_instance(linkfs* fs_ptr) {
    if (fs_ptr) {
        linkfs_destroy_file_vector(fs_ptr->files);
        LINKFS_FREE(fs_ptr);
    }
}

// fs instance info

size_t linkfs_file_count(const linkfs* const fs_ptr) {
    if (fs_ptr) {
        return fs_ptr->files->size;
    }
    return 0;
}

size_t linkfs_total_size(const linkfs* const fs_ptr) {
    if (fs_ptr) {
        size_t total_size = 0;
        for (size_t i = 0; i < fs_ptr->files->size; i++) {
            total_size += fs_ptr->files->entries[i]->block_size * fs_ptr->files->entries[i]->block_count;
        }
        return total_size;
    }
    return 0;
}

// file API

linkfs_file_t* linkfs_open_new_file(linkfs* fs_ptr, const char* filename, size_t block_size) {
    if (fs_ptr) {
        return linkfs_file_vector_append_new(fs_ptr->files, filename, block_size);
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

linkfs_file_t* linkfs_open_file(linkfs* fs_ptr, const char* filename, char mode) {
    if (fs_ptr) {
        linkfs_file_t* file_ptr = linkfs_file_vector_find(fs_ptr->files, filename);
        if (file_ptr) {
            // exists
            if (file_ptr->flags & LINKFS_FILE_LOCKED) {
                LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "file '%s' is already opened\n", filename);
                return NULL;
            }
            if (mode == 'w') {
                // remove existing blocks
                linkfs_cluster_t* current_cluster = file_ptr->start;
                while (current_cluster) {
                    linkfs_cluster_t* next_cluster = current_cluster->next;
                    linkfs_destroy_cluster(current_cluster);
                    current_cluster = next_cluster;
                }
                size_t block_size = file_ptr->block_size;
                linkfs_set_default_file(file_ptr, block_size);
                file_ptr->flags |= LINKFS_FILE_LOCKED | LINKFS_FILE_WRITE;
                return file_ptr;
            }
            else if (mode == 'r') {
                file_ptr->flags |= LINKFS_FILE_LOCKED | LINKFS_FILE_READ;
                return file_ptr;
            }
        }
        else {
            // new file should be created externally
            return NULL;
        }
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

size_t linkfs_read_file(linkfs_file_t* file_ptr, const linkfs_memory_block_t* const buffer) {
    if (file_ptr && buffer && buffer->size <= file_ptr->size) {
        size_t read = file_ptr->current_index * file_ptr->block_size + file_ptr->current_byte;
        size_t length = buffer->size;
        length = length > file_ptr->size - read ? file_ptr->size - read : length;
        size_t requested = length;
        size_t buffer_offset = 0;
        while (length) {
            size_t remains_in_block = length > file_ptr->block_size - file_ptr->current_byte ? file_ptr->block_size - file_ptr->current_byte : length;
            memcpy(buffer->data + buffer_offset, file_ptr->current->block->data + file_ptr->current_byte, remains_in_block);
            length -= remains_in_block;
            buffer_offset += remains_in_block;
            file_ptr->current_byte += remains_in_block;
            if (length) {
                file_ptr->current = file_ptr->current->next;
                file_ptr->current_index++;
                file_ptr->current_byte = 0;
            }
        }
        return requested;
    }
    return 0;
}

size_t linkfs_write_file(linkfs_file_t* file_ptr, const linkfs_memory_block_t* const buffer) {
    if (file_ptr) {
        size_t write_bytes = buffer->size;
        size_t buffer_offset = 0;
        while (1) {
            size_t remains_in_block = file_ptr->block_size - file_ptr->current_byte;
            size_t bytes_can_be_written = write_bytes > remains_in_block ? remains_in_block : write_bytes;
            memcpy(file_ptr->current->block->data + file_ptr->current_byte, buffer->data + buffer_offset, bytes_can_be_written);
            write_bytes -= bytes_can_be_written;
            file_ptr->crc = crc32_ccit_update(buffer->data + buffer_offset, bytes_can_be_written, file_ptr->crc ^ 0xFFFFFFFF);
            if (write_bytes == 0) {
                break;
            }
            buffer_offset += bytes_can_be_written;
            linkfs_file_append_cluster(file_ptr);
        }
        return buffer->size;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return 0;
}

void linkfs_reset_file_cursor(linkfs_file_t* file_ptr) {
    if (file_ptr) {
        file_ptr->current = file_ptr->start;
        file_ptr->current_index = 0;
        file_ptr->current_byte = 0;
    }
}

int32_t linkfs_close_file(linkfs_file_t* file_ptr) {
    if (file_ptr) {
        if (file_ptr->flags & LINKFS_FILE_LOCKED) {
            file_ptr->current = file_ptr->start;
            file_ptr->current_index = 0;
            file_ptr->current_byte = 0;
            file_ptr->flags = 0;
            return 0;
        }
    }
    return -1;
}

uint32_t linkfs_remove_file(linkfs* fs_ptr, linkfs_file_t* file_ptr) {
    if (fs_ptr) {
        return linkfs_file_vector_remove(fs_ptr->files, file_ptr);
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return 0;
}

int32_t linkfs_remove_file_str(linkfs* fs_ptr, const char* filename) {
    if (fs_ptr) {
        return linkfs_file_vector_remove_str(fs_ptr->files, filename);
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return -1;
}

linkfs_file_t* linkfs_find_file(linkfs* fs_ptr, const char* filename) {
    if (fs_ptr) {
        return linkfs_file_vector_find(fs_ptr->files, filename);
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

// walk over all files if needed

size_t linkfs_walk_over_all_files(const linkfs* const fs_ptr, void* arg, void(*procedure)(linkfs_file_t* file_ptr, void* data)) {
    if (fs_ptr) {
        for (size_t i = 0; i < fs_ptr->files->size; i++) {
            procedure(fs_ptr->files->entries[i], arg);
        }
        return fs_ptr->files->size;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return 0;
}
