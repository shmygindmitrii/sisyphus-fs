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
    file_ptr->start = linkfs_create_cluster(block_size);
    file_ptr->current = file_ptr->start;
    file_ptr->props.block_size = block_size;
    file_ptr->props.block_count = 1;
    file_ptr->props.size = 0;
    file_ptr->props.crc = 0;
    file_ptr->props.current_index = 0;
    file_ptr->props.current_byte = 0;
    file_ptr->props.flags = 0;
}

linkfs_file_t* linkfs_create_file(const char* filename, size_t block_size) {
    linkfs_file_t* file_ptr = LINKFS_ALLOC(sizeof(linkfs_file_t));
    file_ptr->filename = linkfs_create_string(filename);
    linkfs_set_default_file(file_ptr, block_size);
    return file_ptr;
}

size_t linkfs_file_binary_size(const linkfs_file_t* const file_ptr) {
    if (file_ptr) {
        size_t file_binary_size = 4 + file_ptr->filename->length + sizeof(linkfs_file_props_t) + file_ptr->props.size;
        return file_binary_size;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_ptr is NULL\n", __FILE__, __LINE__);
    return 0;
}

linkfs_memory_block_t* linkfs_create_memory_block_from_file(const linkfs_file_t* const file_ptr) {
    if (file_ptr) {
        size_t binary_size = linkfs_file_binary_size(file_ptr);
        linkfs_memory_block_t* block_ptr = linkfs_create_memory_block(binary_size);
        size_t block_offset = 0;
        *(uint32_t*)block_ptr->data = (uint32_t)file_ptr->filename->length;
        block_offset += 4;
        memcpy(block_ptr->data + block_offset, file_ptr->filename->content, file_ptr->filename->length);
        block_offset += file_ptr->filename->length;
        memcpy(block_ptr->data + block_offset, &file_ptr->props, sizeof(linkfs_file_props_t));
        block_offset += sizeof(linkfs_file_props_t);
        linkfs_cluster_t* cluster_ptr = file_ptr->start;
        size_t file_size = file_ptr->props.size;
        while (file_size) {
            size_t block_filled = file_size < file_ptr->props.block_size ? file_size : file_ptr->props.block_size;
            memcpy(block_ptr->data + block_offset, cluster_ptr->block->data, block_filled);
            block_offset += block_filled;
            file_size -= block_filled;
            cluster_ptr = cluster_ptr->next;
        }
        LINKFS_ASSERT(cluster_ptr == NULL);
        return block_ptr;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

linkfs_file_t* linkfs_create_file_from_memory_block(const linkfs_memory_block_t* const block_ptr) {
    if (block_ptr) {
        uint32_t filename_length = *(uint32_t*)block_ptr->data;
        const char* filename = block_ptr->data[4];
        const linkfs_file_props_t* props_ptr = (linkfs_file_props_t*)(block_ptr->data + filename_length + 4);
        linkfs_file_t* file_ptr = linkfs_create_file(filename, props_ptr->block_size);
        size_t file_size = file_ptr->props.size;
        size_t block_offset = filename_length + 4;
        file_ptr->start = linkfs_create_cluster(props_ptr->block_size);
        file_ptr->current = file_ptr->start;
        while (file_size) {
            size_t block_size = file_size < props_ptr->block_size ? file_size : props_ptr->block_size;
            memcpy(file_ptr->current->block->data, block_ptr->data + block_offset, block_size);
            file_ptr->current->next = linkfs_create_cluster(props_ptr->block_size);
            file_ptr->current = file_ptr->current->next;
            block_offset += block_size;
            file_size -= block_size;
        }
        memcpy(&file_ptr->props, props_ptr, sizeof(linkfs_file_props_t));
        linkfs_close_file(file_ptr);
        return file_ptr;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> block_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

linkfs_cluster_t* linkfs_file_append_cluster(linkfs_file_t* file_ptr) {
    if (file_ptr) {
        file_ptr->current->next = linkfs_create_cluster(file_ptr->props.block_size);
        file_ptr->current = file_ptr->current->next;
        file_ptr->props.current_index++;
        file_ptr->props.block_count++;
        file_ptr->props.current_byte = 0;
        file_ptr->props.size += file_ptr->props.block_size;
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
        file_ptr->start = NULL;
        file_ptr->current = NULL;
        file_ptr->props.block_size = 0;
        file_ptr->props.block_count = 0;
        file_ptr->props.size = 0;
        file_ptr->props.crc = 0;
        file_ptr->props.current_index = 0;
        file_ptr->props.current_byte = 0;
        file_ptr->props.flags = 0;
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

void linkfs_file_vector_reserve(linkfs_file_vector_t* file_vector_ptr, const size_t new_capacity) {
    if (file_vector_ptr) {
        for (size_t i = new_capacity; i < file_vector_ptr->size; i++) {
            linkfs_destroy_file(file_vector_ptr->entries[i]);
            file_vector_ptr->entries[i] = NULL;
        }
        if (new_capacity) {
            linkfs_file_t** files = LINKFS_ALLOC(new_capacity * sizeof(linkfs_file_t*));
            memcpy(files, file_vector_ptr->entries, new_capacity * sizeof(linkfs_file_t*));
            LINKFS_FREE(file_vector_ptr->entries);
            file_vector_ptr->entries = files;
        }
        else {
            LINKFS_FREE(file_vector_ptr->entries);
            file_vector_ptr->entries = NULL;
        }
        file_vector_ptr->capacity = new_capacity;
        file_vector_ptr->size = file_vector_ptr->size > new_capacity ? new_capacity : file_vector_ptr->size;
    }
    else {
        LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_vector_ptr is NULL\n", __FILE__, __LINE__);
    }
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

void linkfs_file_vector_append(linkfs_file_vector_t* file_vector_ptr, const linkfs_file_t* const file_ptr) {
    if (file_vector_ptr) {
        LINKFS_ASSERT(file_ptr);
        if (file_vector_ptr->size == file_vector_ptr->capacity) {
            size_t new_capacity = file_vector_ptr->capacity ? file_vector_ptr->capacity * 2 : 8ULL;
            linkfs_file_vector_reserve(file_vector_ptr, new_capacity);
        }
        file_vector_ptr->entries[file_vector_ptr->size++] = file_ptr;
    }
    else {
        LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_vector_ptr is NULL\n", __FILE__, __LINE__);
    }
}

linkfs_file_t* linkfs_file_vector_append_new(linkfs_file_vector_t* file_vector_ptr, const char* filename, size_t block_size) {
    if (file_vector_ptr) {
        linkfs_file_t* file_ptr = linkfs_create_file(filename, block_size);
        linkfs_file_vector_append(file_vector_ptr, file_ptr);
        return file_ptr;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_vector_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

int32_t linkfs_file_vector_remove(linkfs_file_vector_t* file_vector_ptr, const linkfs_file_t* const file_ptr) {
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
            total_size += fs_ptr->files->entries[i]->props.block_size * fs_ptr->files->entries[i]->props.block_count;
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
            if (file_ptr->props.flags & LINKFS_FILE_LOCKED) {
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
                size_t block_size = file_ptr->props.block_size;
                linkfs_set_default_file(file_ptr, block_size);
                file_ptr->props.flags |= LINKFS_FILE_LOCKED | LINKFS_FILE_WRITE;
                return file_ptr;
            }
            else if (mode == 'r') {
                file_ptr->props.flags |= LINKFS_FILE_LOCKED | LINKFS_FILE_READ;
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
    if (file_ptr && buffer && buffer->size <= file_ptr->props.size) {
        size_t read = file_ptr->props.current_index * file_ptr->props.block_size + file_ptr->props.current_byte;
        size_t length = buffer->size;
        length = length > file_ptr->props.size - read ? file_ptr->props.size - read : length;
        size_t requested = length;
        size_t buffer_offset = 0;
        while (length) {
            size_t remains_in_block = length > file_ptr->props.block_size - file_ptr->props.current_byte ? file_ptr->props.block_size - file_ptr->props.current_byte : length;
            memcpy(buffer->data + buffer_offset, file_ptr->current->block->data + file_ptr->props.current_byte, remains_in_block);
            length -= remains_in_block;
            buffer_offset += remains_in_block;
            file_ptr->props.current_byte += remains_in_block;
            if (length) {
                file_ptr->current = file_ptr->current->next;
                file_ptr->props.current_index++;
                file_ptr->props.current_byte = 0;
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
            size_t remains_in_block = file_ptr->props.block_size - file_ptr->props.current_byte;
            size_t bytes_can_be_written = write_bytes > remains_in_block ? remains_in_block : write_bytes;
            memcpy(file_ptr->current->block->data + file_ptr->props.current_byte, buffer->data + buffer_offset, bytes_can_be_written);
            write_bytes -= bytes_can_be_written;
            file_ptr->props.crc = crc32_ccit_update(buffer->data + buffer_offset, bytes_can_be_written, file_ptr->props.crc ^ 0xFFFFFFFF);
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
        file_ptr->props.current_index = 0;
        file_ptr->props.current_byte = 0;
    }
}

int32_t linkfs_close_file(linkfs_file_t* file_ptr) {
    if (file_ptr && (file_ptr->props.flags & LINKFS_FILE_LOCKED) != 0) {
        file_ptr->current = file_ptr->start;
        file_ptr->props.current_index = 0;
        file_ptr->props.current_byte = 0;
        file_ptr->props.flags = 0;
        return 0;
    }
    if (file_ptr == NULL) {
        LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_ptr is NULL\n", __FILE__, __LINE__);
        return -1;
    }
    else {
        LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file '%s' was not opened\n", __FILE__, __LINE__, file_ptr->filename->content);
        return -1;
    }
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

linkfs_memory_block_t* linkfs_to_memory_block(const linkfs* const fs_ptr) {
    if (fs_ptr) {
        size_t total_binary_size = 4; // file count
        for (size_t i = 0; i < fs_ptr->files->size; i++) {
            const linkfs_file_t* const file_ptr = fs_ptr->files->entries[i];
            total_binary_size += 4 + linkfs_file_binary_size(file_ptr);
        }
        linkfs_memory_block_t* block_ptr = linkfs_create_memory_block(total_binary_size);
        *(uint32_t*)block_ptr->data = (uint32_t)fs_ptr->files->size;
        size_t block_offset = 4;
        for (size_t i = 0; i < fs_ptr->files->size; i++) {
            const linkfs_file_t* const file_ptr = fs_ptr->files->entries[i];
            const linkfs_memory_block_t* const file_block_ptr = linkfs_create_memory_block_from_file(file_ptr);
            if (file_block_ptr) {
                *(uint32_t*)(block_ptr->data + block_offset) = (uint32_t)file_block_ptr->size;
                block_offset += 4;
                memcpy(block_ptr->data + block_offset, file_block_ptr->data, file_block_ptr->size);
                block_offset += file_block_ptr->size;
                linkfs_destroy_memory_block(block_ptr);
            }
            else {
                LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> file_block_ptr is NULL\n", __FILE__, __LINE__);
            }
        }
        LINKFS_ASSERT(block_offset == block_ptr->size);
        return block_ptr;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> fs_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}

linkfs* linkfs_from_memory_block(const linkfs_memory_block_t* const block_ptr) {
    if (block_ptr) {
        linkfs* fs_ptr = linkfs_create_instance();
        const size_t file_count = *(uint32_t*)block_ptr->data;
        size_t block_offset = 4;
        for (uint32_t i = 0; i < file_count; i++) {
            linkfs_memory_block_t block;
            block.size = (size_t)(*(uint32_t*)(block_ptr->data + block_offset));
            block_offset += 4;
            block.data = block_ptr->data + block_offset;
            const linkfs_file_t* const file_ptr = linkfs_create_file_from_memory_block(&block);
            linkfs_file_vector_append(fs_ptr->files, file_ptr);
            block_offset += block.size;
        }
        return fs_ptr;
    }
    LINKFS_DEBUGBREAK(LINKFS_PRINT_ERROR "%s(%d) -> block_ptr is NULL\n", __FILE__, __LINE__);
    return NULL;
}
