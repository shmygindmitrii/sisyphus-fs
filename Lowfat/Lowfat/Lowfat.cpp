// Lowfat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <vector>
//
#include <iostream>
#include <inttypes.h>
#include <memory>
#include <cstring>
#include <cassert>
#include <bitset>
#include <ctime>
#include <chrono>

typedef uint8_t byte;

#define LF_OK                                0
#define LF_NONE                             -1

#define LF_FILE_LOCKED                       1
#define LF_FILE_READ                         2
#define LF_FILE_WRITE                        4

#define LF_ERROR_DATA_TABLE_ENDED           -2
#define LF_ERROR_SPACE_ENDED                -3
#define LF_ERROR_SYSTEM_SECTION             -4

#define LF_ERROR_FILE_NOT_FOUND             -5
#define LF_ERROR_FILE_ALREADY_OPENED        -6
#define LF_ERROR_FILE_NAME_NULL             -7
#define LF_ERROR_FILE_NAME_TOO_LONG         -8
#define LF_ERROR_FILE_WRONG_MODE            -9
#define LF_ERROR_FILE_READ_SIZE_OVERFLOW    -10

#define CRC32_DEFAULT_VALUE                  0xFFFFFFFF

// tail addition
static inline void acquire_next_free(int32_t* table_next, int32_t* table_prev, int32_t* last_busy, int32_t* first_free) {
    int32_t cur_free = *first_free;
    assert(table_prev[cur_free] == LF_NONE);
    *first_free = table_next[*first_free];
    if (*first_free != LF_NONE) {
        table_prev[*first_free] = LF_NONE;
    }
    assert(table_next[*last_busy] == LF_NONE);
    table_prev[cur_free] = *last_busy;
    table_next[*last_busy] = cur_free;
    table_next[cur_free] = LF_NONE;
    *last_busy = cur_free;
}

static inline void free_busy_range(int32_t* table_next, int32_t* table_prev, int32_t first, int32_t last, int32_t* last_busy, int32_t* first_free) {
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
        assert(table_prev[*first_free] == LF_NONE);
        table_prev[*first_free] = last;
    }
    *first_free = first;
}

static inline uint32_t calculate_range_length(int32_t* table_next, int32_t first, int32_t last) {
    assert(first >= 0 && last >= 0);
    uint32_t node_count = 1;
    while (first != last) {
        first = table_next[first];
        node_count++;
    }
    return node_count;
}

// based on 0xEDB88320 = (reverse bits of 0x04C11DB7 to revert polynomial order) << 5
// calculated myself, but you may compare it with https://web.mit.edu/freebsd/head/sys/libkern/crc32.c

/*
void generate_crc32_lookup_table(uint32_t revkey, uint32_t* table) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t cur = i;
        for (uint32_t j = 0; j < 8; j++) {
            cur = (cur & 1) ? ((cur >> 1) ^ revkey) : (cur >> 1);
        }
        table[i] = cur;
    }
}
*/

const uint32_t crc32_ccit_lookup_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static inline uint32_t update_crc32_ccit(uint8_t* data, uint32_t size, uint32_t crc) {
    for (uint32_t i = 0; i < size; i++) {
        crc = crc32_ccit_lookup_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

namespace lofat {
#pragma pack(push, 1)
    struct fileprops {
        uint64_t mtime = 0;
        uint32_t size = 0;
        uint32_t crc32 = CRC32_DEFAULT_VALUE;
        int32_t first_cluster = -1;
        int32_t last_cluster = -1;
        int32_t current_cluster = 0;   // not more than 65536 clusters
        uint16_t current_byte = 0;     // not more than 65536 bytes in cluster
        uint8_t locked = 0;

        void reset() {
            mtime = 0;
            size = 0;
            crc32 = CRC32_DEFAULT_VALUE;
            first_cluster = LF_NONE;
            last_cluster = LF_NONE;
            current_cluster = LF_NONE;
            current_byte = 0;
            locked = 0;
        }
    };

    struct fileinfo {
        char* name = nullptr;
        fileprops* props = nullptr;

        fileinfo(uint8_t* name_ptr, uint8_t* props_ptr): name((char*)name_ptr), props((fileprops*)props_ptr) {}
    };

    struct filename_t {
        std::vector<char> name;
        filename_t(uint32_t size) {
            assert(size > 0);
            name.resize(size);
            std::fill(name.begin(), name.end(), '\0');
        }
        char* data() {
            return &name[0];
        }
        uint32_t size() {
            return (uint32_t)name.size();
        }
    };

    enum class EFsInitAction {
        Reset,
        Use
    };

    class fs {
    public:
        static constexpr uint64_t start_marker = 11348751673753212928ULL;   // this is random marker of fs beginning
        static constexpr uint64_t end_marker = 907403631122679808ULL;       // this is random marker of fs ending
        
        fs(uint32_t cluster_size, uint32_t cluster_count, uint32_t filename_length, uint8_t* data, const EFsInitAction action): _data(data) {
            assert(data != nullptr);
            _total_size = cluster_count * cluster_size;
            // now we should have place for everything
            _cluster_size = reinterpret_cast<uint32_t*>(_data);
            _cluster_count = _cluster_size + 1;
            _filename_length = _cluster_size + 2;
            *_cluster_size = cluster_size;
            *_cluster_count = cluster_count;
            *_filename_length = filename_length;
            //
            const uint32_t fs_info_size = 6 * sizeof(uint32_t) + 4 * sizeof(int32_t); // just to mark difference
            _system_used_size = fs_info_size + (sizeof(fileprops) + filename_length + sizeof(int32_t) * 4) * cluster_count;
            _system_used_clusters = _system_used_size / cluster_size + (int)(_system_used_size % cluster_size > 0);
            _last_system_cluster = _system_used_clusters - 1;
            //
            assert(_system_used_clusters < cluster_count);
            //
            this->set_addresses();
            if (action == EFsInitAction::Reset) {
                // nullify what it was
                this->reset();
            }
        }

        void set_addresses() {
            _used_memory = _cluster_size + 3;
            _used_cluster_count = _cluster_size + 4;
            _file_count = _cluster_size + 5;
            _filename_table_busy_tail = reinterpret_cast<int32_t*>(_file_count) + 1;
            _filename_table_free_head = _filename_table_busy_tail + 1;
            _data_table_busy_tail = _filename_table_busy_tail + 2;
            _data_table_free_head = _filename_table_busy_tail + 3;
            // 40 bytes used for common for fs values
            const uint32_t fileinfos_offset = 40;
            const uint32_t fileinfo_stride = sizeof(fileprops) + *_filename_length;
            const uint32_t fileinfo_size = fileinfo_stride * (*_cluster_count);
            _filename_table_next = reinterpret_cast<int32_t*>(&_data[fileinfos_offset + fileinfo_size]);
            _filename_table_prev = _filename_table_next + (*_cluster_count);
            _data_table_next = _filename_table_prev + (*_cluster_count);
            _data_table_prev = _data_table_next + (*_cluster_count);
            _filenames = _data + fileinfos_offset;
            _fileprops = _data + fileinfos_offset + (*_filename_length);
        }

        void reset() {
            *_used_memory = _system_used_size;
            *_used_cluster_count = _system_used_clusters;
            *_filename_table_busy_tail = LF_NONE;
            *_data_table_busy_tail = LF_NONE;
            const uint32_t fileinfo_stride = sizeof(fileprops) + *_filename_length;
            for (uint32_t i = 0; i < *_cluster_count; i++) {
                memset(_filenames + i * fileinfo_stride, 0, *_filename_length);
                fileprops* props_i = reinterpret_cast<fileprops*>(_fileprops + i * fileinfo_stride);
                props_i->reset();
                _filename_table_next[i] = i + 1;
                _filename_table_prev[i] = i - 1;
                _data_table_next[i] = i + 1;
                _data_table_prev[i] = i - 1;
            }
            _filename_table_next[(*_cluster_count) - 1] = LF_NONE;
            *_filename_table_busy_tail = _last_system_cluster;
            *_filename_table_free_head = _last_system_cluster + 1;
            _filename_table_next[(*_filename_table_busy_tail)] = LF_NONE;
            _filename_table_prev[(*_filename_table_free_head)] = LF_NONE;

            for (uint32_t i = 0; i < _system_used_clusters; i++) {
                snprintf((char*)(_filenames + i * fileinfo_stride), (*_filename_length), "SYSTEM%d", i);
                fileprops* props_i = reinterpret_cast<fileprops*>(_fileprops + i * fileinfo_stride);
                props_i->size = (*_cluster_size);
            }

            _data_table_next[(*_cluster_count) - 1] = LF_NONE;
            *_data_table_busy_tail = _last_system_cluster;
            *_data_table_free_head = _last_system_cluster + 1;
            _data_table_next[*_data_table_busy_tail] = LF_NONE;
            _data_table_prev[*_data_table_free_head] = LF_NONE;
        }

        int32_t open(const char* filename, char mode) {
            if (filename == nullptr) {
                return LF_ERROR_FILE_NAME_NULL;
            }
            size_t filename_len = strlen(filename);
            if (filename_len > (*_filename_length) - 1) {
                return LF_ERROR_FILE_NAME_TOO_LONG;
            }
            int32_t fd = this->find(filename);
            if (fd >= 0 && fd < (int32_t)_system_used_clusters) {
                return LF_ERROR_SYSTEM_SECTION;
            }
            const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
            if (mode == 'r') {
                if (fd >= 0) {
                    fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                    fi.props->locked |= LF_FILE_READ;
                }
                return fd;
            }
            else if (mode == 'w') {
                if (fd >= 0) {
                    // remove existing
                    this->remove(fd);
                    fd = LF_ERROR_FILE_NOT_FOUND;
                }
                if (fd == LF_ERROR_FILE_ALREADY_OPENED) {
                    return LF_ERROR_FILE_ALREADY_OPENED;
                }
                if (*_data_table_free_head == LF_NONE) {
                    return LF_ERROR_SPACE_ENDED;
                }
                assert(fd == LF_ERROR_FILE_NOT_FOUND);
                // LF_FILE_ERROR_NOT_FOUND - create new
                acquire_next_free(_filename_table_next, _filename_table_prev, _filename_table_busy_tail, _filename_table_free_head);
                fd = *_filename_table_busy_tail;
                // put busy node to the head of list
                acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                (*_used_cluster_count)++;
                // add to _fileinfos first free first_cluster
                fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                sprintf_s(fi.name, (*_filename_length), filename);
                fi.props->mtime = 0;
                fi.props->size = 0;
                fi.props->first_cluster = *_data_table_busy_tail;
                fi.props->last_cluster = *_data_table_busy_tail;
                fi.props->current_cluster = *_data_table_busy_tail;
                fi.props->current_byte = 0;
                fi.props->locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                (*_file_count)++;
                return fd;
            }
            return LF_ERROR_FILE_WRONG_MODE;
        }
        int32_t read(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
            if (fd >= 0 && fd < (int32_t)_system_used_clusters) {
                return LF_ERROR_SYSTEM_SECTION;
            }
            const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
            if (fd > (int32_t)_last_system_cluster) {
                fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                uint32_t read_size = elem_size * count;
                if (read_size > fi.props->size) {
                    return LF_ERROR_FILE_READ_SIZE_OVERFLOW;
                }
                uint32_t buf_offset = 0;
                while (read_size > 0) {
                    uint32_t mem_can_read = (*_cluster_size) - fi.props->current_byte;
                    if (mem_can_read == 0) {
                        fi.props->current_cluster = _data_table_next[fi.props->current_cluster];
                        fi.props->current_byte = 0;
                        mem_can_read = (*_cluster_size);
                    }
                    if (mem_can_read > read_size) {
                        mem_can_read = read_size;
                    }
                    //
                    uint32_t offset = fi.props->current_cluster * (*_cluster_size) + fi.props->current_byte;
                    memcpy(buf + buf_offset, &_data[offset], mem_can_read);
                    //
                    fi.props->current_byte += (uint16_t)mem_can_read;
                    buf_offset += mem_can_read;
                    read_size -= mem_can_read;
                }
                return LF_OK;
            }
            return LF_ERROR_FILE_NOT_FOUND;
        }
        int32_t write(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
            if (fd >= 0) {
                // always write new
                int32_t total_write_size = elem_size * count;
                uint32_t buf_offset = 0;
                const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
                fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                while (total_write_size > 0) {
                    int32_t mem_can_write = (*_cluster_size) - fi.props->current_byte;
                    if (mem_can_write == 0) {
                        // go to the next cluster
                        assert((*_data_table_free_head) != LF_NONE);
                        if ((*_data_table_free_head) == LF_NONE) {
                            return LF_ERROR_SPACE_ENDED;
                        }
                        acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                        fi.props->last_cluster = *_data_table_busy_tail;
                        fi.props->current_byte = 0;
                        mem_can_write = (*_cluster_size);
                        (*_used_cluster_count)++;
                    }
                    if (mem_can_write >= total_write_size) {
                        mem_can_write = total_write_size;
                    }
                    uint32_t offset = fi.props->last_cluster * (*_cluster_size) + fi.props->current_byte;
                    //
                    memcpy(&_data[offset], buf + buf_offset, mem_can_write);
                    //
                    fi.props->current_byte += (uint16_t)mem_can_write;
                    fi.props->size += mem_can_write;
                    buf_offset += mem_can_write;
                    total_write_size -= mem_can_write;
                }
                fi.props->crc32 = update_crc32_ccit(buf, elem_size * count, fi.props->crc32);
                (*_used_memory) += elem_size * count;
                return count;
            }
            else {
#if _DEBUG
                __debugbreak();
#endif
                return -1;
            }
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
                fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                fi.props->locked = 0;
                fi.props->current_cluster = fi.props->first_cluster;
                fi.props->current_byte = 0;
                assert(fi.props->size != 0);
#if _DEBUG
                printf("Close descriptor %d of size %u and crc32 = %u, remains %u\n", fd, fi.props->size, fi.props->crc32, (uint32_t)free_available_mem_size());
#endif
                return LF_OK;
            }
            return fd;
        }
        
        int32_t remove(const char* filename) {
            int32_t fd = this->find(filename);
            if (fd >= LF_OK) {
                return this->remove(fd);
            }
            return fd;
        }

        int32_t find(const char* filename) const {
            // linear search
            int32_t busy_head = _filename_table_next[_last_system_cluster];
            const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
            while (busy_head != LF_NONE) {
                if (strcmp((char*)(_filenames + busy_head * fileinfo_stride), filename) == 0) {
                    return busy_head;
                }
                busy_head = _filename_table_next[busy_head];
            }
            return LF_ERROR_FILE_NOT_FOUND;
        }

        const fileinfo stat(int32_t fd) const {
            assert(fd >= 0 && fd < (int32_t)(*_cluster_count));
            if (fd >= 0 && fd < (int32_t)(*_cluster_count)) {
                const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
                return fileinfo(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
            }
            else {
                return fileinfo(nullptr, nullptr);
            }
        }

        fileinfo stat(const char* name) const {
            int fd = find(name);
            if (fd != LF_ERROR_FILE_NOT_FOUND) {
                const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
                return fileinfo(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
            }
            fileinfo empty(nullptr, nullptr);
            return empty;
        }

        uint32_t free_mem_size() {
            // real free space, that includes unused clusters memory
            return _total_size - (*_used_memory);
        }

         uint32_t free_available_mem_size() {
            // real writable amount of memory
            return ((*_cluster_count) - (*_used_cluster_count)) * (*_cluster_size);
        }

        int32_t remove(int fd) {
            assert(fd >= 0 && fd < *_cluster_count);
            if (fd >= 0 && fd < (int32_t)(*_cluster_count)) {
                // busy clusters handle
                const uint32_t fileinfo_stride = sizeof(fileprops) + (*_filename_length);
                fileinfo fi(_filenames + fd * fileinfo_stride, _fileprops + fd * fileinfo_stride);
                int32_t first_cluster = fi.props->first_cluster;
                int32_t last_cluster = fi.props->last_cluster;
                uint32_t freed_clusters = calculate_range_length(_data_table_next, first_cluster, last_cluster);
                (*_used_cluster_count) -= freed_clusters;
                free_busy_range(_data_table_next, _data_table_prev, first_cluster, last_cluster, _data_table_busy_tail, _data_table_free_head);
                // 
                free_busy_range(_filename_table_next, _filename_table_prev, fd, fd, _filename_table_busy_tail, _filename_table_free_head);
                // reset properties
                (*_used_memory) -= fi.props->size;
#if _DEBUG
                printf("Remove file '%s' of size %u\n", fi.name, fi.props->size);
#endif
                memset(fi.name, 0, *_filename_length);
                fi.props->reset();
                (*_file_count)--;
                return freed_clusters;
            }
            else {
                return -1;
            }
        }

        uint32_t file_count() const {
            return (*_file_count);
        }

        uint8_t* raw() {
            return _data;
        }

        uint32_t filename_length() const {
            return (*_filename_length);
        }

        uint32_t cluster_size() const {
            return (*_cluster_size);
        }

        uint32_t cluster_count() const {
            return (*_cluster_count);
        }

        uint32_t total_size() const {
            return (*_cluster_count) * (*_cluster_size);
        }

        uint32_t system_used_clusters() const {
            return _system_used_clusters;
        }

        uint32_t system_used_size() const {
            return _system_used_size;
        }
    private:
        // this is the only real data
        uint8_t* _data = nullptr; // of total_size
        //
        uint32_t* _cluster_size = nullptr;
        uint32_t* _cluster_count = nullptr;
        uint32_t* _filename_length = nullptr;
        uint32_t* _used_memory = nullptr;
        uint32_t* _used_cluster_count = nullptr;
        uint32_t* _file_count = nullptr; // 0
        int32_t* _filename_table_busy_tail = nullptr; // LF_NONE
        int32_t* _filename_table_free_head = nullptr; // 0
        int32_t* _data_table_busy_tail = nullptr; // LF_NONE
        int32_t* _data_table_free_head = nullptr; // 0
        // arrays of cluster_count elements
        uint8_t* _filenames = nullptr;
        uint8_t* _fileprops = nullptr;
        int32_t* _filename_table_next = nullptr;
        int32_t* _filename_table_prev = nullptr;
        int32_t* _data_table_next = nullptr;
        int32_t* _data_table_prev = nullptr;
        //
        uint32_t _total_size = 0;
        uint32_t _system_used_size = 0;
        uint32_t _system_used_clusters = 0;
        uint32_t _last_system_cluster = LF_NONE;
    };
#pragma pack(pop)
}

uint32_t fill_random_byte_buffer_and_calc_crc32(std::vector<byte>& mem) {
    for (uint32_t i = 0; i < (uint32_t)mem.size(); i++) {
        mem[i] = (uint8_t)(rand() % 256);
    }
    return update_crc32_ccit(mem.data(), (uint32_t)mem.size(), CRC32_DEFAULT_VALUE);
}

struct MemAmount_t {
    size_t megabytes = 0;
    size_t kilobytes = 0;
    size_t bytes = 0;

    MemAmount_t& operator+=(size_t _bytes) {
        bytes += _bytes;
        size_t kbytes = bytes / 1024;
        bytes -= kbytes * 1024;
        kilobytes += kbytes;
        size_t mbytes = kilobytes / 1024;
        kilobytes -= mbytes * 1024;
        megabytes += mbytes;
        return *this;
    }
};

void test_fs_readback(lofat::fs& filesys, double test_period) {
    
    uint32_t file_idx = 0;
    std::vector<lofat::filename_t> filenames;
    std::vector<uint32_t> crcs;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    uint32_t cycle_idx = 0;
    uint32_t writes_count = 0;
    MemAmount_t rewritten_memory{};
    
    while (elapsed.count() < test_period) {
        size_t available = filesys.free_available_mem_size(); // not tight, free clusters * cluster_size
        if (available) {
            // have a place to write
            size_t random_filesize = (rand() % filesys.total_size()) % (available - filesys.cluster_size() / 4) + filesys.cluster_size() / 4;
            if (cur_empty_file_idx == (uint32_t)crcs.size()) {
                // push_back new one
                crcs.push_back(0);
                filenames.push_back(lofat::filename_t(filesys.filename_length()));
            }
            std::vector<byte> mem(random_filesize);
            crcs[cur_empty_file_idx] = fill_random_byte_buffer_and_calc_crc32(mem);
            lofat::filename_t& filename = filenames[cur_empty_file_idx];
            snprintf(filename.data(), filename.size(), "test_file_%u_%u.bin", cycle_idx, cur_empty_file_idx);
#if _DEBUG
            printf("try to save \"%s\" of size %u\n", filename.data(), (uint32_t)random_filesize);
#endif
            int32_t fd = filesys.open(filename.data(), 'w');
            uint32_t written = filesys.write(mem.data(), (uint32_t)mem.size(), 1, fd);
            filesys.close(fd);
            assert(written == 1);
            lofat::fileinfo finfo = filesys.stat(fd);
            assert(finfo.name != nullptr);
            assert(crcs[cur_empty_file_idx] == finfo.props->crc32);
            rewritten_memory += mem.size();
            cur_empty_file_idx++;
            writes_count++;
        } 
        else {
            // need to free place
            uint32_t files_written = filesys.file_count();
            uint32_t files_to_remove = (rand() % (files_written - 1)) + 1;
#if _DEBUG
            printf("Space finished, free procedure for %u files of %u \n", files_to_remove, files_written);
#endif
            for (uint32_t i = 0; i < files_to_remove; i++) {
                // need a vector of filenames
                uint32_t cur_file_idx = rand() % files_written;
                int fd = filesys.open(filenames[cur_file_idx].data(), 'r');
                assert(fd >= LF_OK);
                lofat::fileinfo finfo = filesys.stat(fd);
                assert(finfo.name != nullptr);
                std::vector<byte> mem(finfo.props->size);
                int32_t read = filesys.read(mem.data(), 1, (uint32_t)mem.size(), fd);
                filesys.close(fd);
                uint32_t test_crc32 = update_crc32_ccit(mem.data(), (uint32_t)mem.size(), CRC32_DEFAULT_VALUE);
                assert(test_crc32 == crcs[cur_file_idx] && test_crc32 == finfo.props->crc32);
                uint32_t freed_clusters = filesys.remove(fd);
                assert(freed_clusters == ((uint32_t)mem.size() / filesys.cluster_size() + ((uint32_t)mem.size() % filesys.cluster_size() > 0)));
                //
#if _DEBUG
                printf("Removed '%s'\n", filenames[cur_file_idx].data());
#endif
                if (cur_file_idx != files_written - 1) {
                    assert(strcmp(filenames[cur_file_idx].data(), filenames[cur_empty_file_idx - 1].data()) != 0);
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    crcs[cur_file_idx] = crcs[files_written - 1];
                }
                filenames[files_written - 1] = lofat::filename_t(filesys.filename_length());
                crcs[files_written - 1] = 0;
                files_written--;
            }
            cur_empty_file_idx -= files_to_remove;
        }
        //
        cycle_idx++;
        //
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
    }
    // remove remained files
    for (uint32_t i = 0; i < cur_empty_file_idx; i++) {
        int fd = filesys.open(filenames[i].data(), 'r');
        assert(fd >= LF_OK);
        lofat::fileinfo finfo = filesys.stat(fd);
        assert(finfo.name != nullptr);
        std::vector<byte> mem(finfo.props->size);
        int32_t read = filesys.read(mem.data(), 1, (uint32_t)mem.size(), fd);
        filesys.close(fd);
        uint32_t test_crc32 = update_crc32_ccit(mem.data(), (uint32_t)mem.size(), CRC32_DEFAULT_VALUE);
        assert(test_crc32 == crcs[i] && test_crc32 == finfo.props->crc32);
        uint32_t freed_clusters = filesys.remove(fd);
        assert(freed_clusters == (mem.size() / filesys.cluster_size() + (mem.size() % filesys.cluster_size() > 0)));
    }
    uint32_t mem_busy = filesys.cluster_count() * filesys.cluster_size() - (uint32_t)filesys.free_mem_size();
    assert(mem_busy == filesys.system_used_size());
    printf("File system randomized RW test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, filesys.total_size());
}

void test_crc32() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), lofat::EFsInitAction::Reset);
    //
    const char test_abc[] = "ABC";
    const char test_d[] = "D";
    uint32_t crc_test_3 = update_crc32_ccit((uint8_t*)test_abc, 3, CRC32_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = update_crc32_ccit((uint8_t*)test_d, 1, crc_test_3);
    printf("ABCD remainder lookuped: %#010x\n", crc_test_3);
    {
        int32_t abc_fd = fat.open("saved_text.txt", 'w');
        fat.write((uint8_t*)test_abc, 3, 1, abc_fd);
        fat.write((uint8_t*)test_d, 1, 1, abc_fd);
        fat.close(abc_fd);
        const lofat::fileinfo& fst = fat.stat(abc_fd);
        printf("File remainder lookuped: %#010x\n", fst.props->crc32);
    }
}

void test_simple_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), lofat::EFsInitAction::Reset);

    const int max_user_file_count = fat.cluster_count() - fat.system_used_clusters();
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat.open(filename, 'w');
        assert(test >= 0);
        int32_t close_res = fat.close(test);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t remove_res = fat.remove(filename);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat.open(filename, 'w');
        int32_t close_res = fat.close(test);
    }
    for (int i = 5; i < max_user_file_count + 5; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i % max_user_file_count);
        int32_t remove_res = fat.remove(filename);
    }
    {
        int32_t test_fd = fat.open("three.txt", 'w');
        uint8_t test_buf[fs_cluster_size * 3] = { 0 };
        memset(test_buf, 1, fs_cluster_size * 3);
        fat.write(test_buf, 1, fs_cluster_size * 3, test_fd);
        int32_t close_res = fat.close(test_fd);
    }
    {
        int32_t test_fd = fat.open("three_and_half.txt", 'w');
        uint8_t test_buf[fs_cluster_size / 2] = { 0 };
        memset(test_buf, 2, fs_cluster_size / 2);
        fat.write(test_buf, 1, fs_cluster_size / 2, test_fd);
        int32_t close_res = fat.close(test_fd);
    }
    {
        char text[1536] = { '\0' };
        int32_t switcher = 1536 / ('z' - 'a' + 1);
        for (int i = 0; i < 1536; i++) {
            text[i] = 'a' + i / switcher;
        }
        int32_t text_fd = fat.open("saved_text.txt", 'w');
        fat.write((uint8_t*)(text), 1, sizeof(text), text_fd);
        fat.close(text_fd);
    }
    {
        int32_t text_fd = fat.open("saved_text.txt", 'r');
        lofat::fileinfo file_info = fat.stat(text_fd);
        char* text = new char[file_info.props->size];
        fat.read((uint8_t*)text, 1, file_info.props->size, text_fd);
        fat.close(text_fd);
        delete[] text;
    }
}

void test_randomized_rw(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), lofat::EFsInitAction::Reset);

    test_fs_readback(fat, duration);
}

void test_randomized_dump(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), lofat::EFsInitAction::Reset);
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cycle_idx = 0;
    while (elapsed.count() < duration) {
        uint32_t file_idx = 0;
        std::vector<uint32_t> crcs;
        std::vector <std::string> filenames;
        size_t available = fat.free_available_mem_size();
        while (available) {
            size_t random_filesize = (rand() % fat.total_size()) % (available - fat.cluster_size() / 4) + fat.cluster_size() / 4;
            std::vector<byte> mem(random_filesize, 0);
            uint32_t crc = fill_random_byte_buffer_and_calc_crc32(mem);
            char filename[fs_filename_max_length] = {};
            snprintf(filename, fs_filename_max_length, "test_file_%d.bin", file_idx);
            int fd = fat.open(filename, 'w');
            fat.write(mem.data(), 1, (uint32_t)mem.size(), fd);
            fat.close(fd);
            available = fat.free_available_mem_size();
            //
            file_idx++;
            crcs.push_back(crc);
            filenames.push_back(filename);
        }
        // finished fullfilling of fs
        std::vector<byte> dumped(fat.total_size() + sizeof(uint64_t) * 2, 0);
        memcpy(&dumped[0], &fat.start_marker, sizeof(uint64_t));
        memcpy(&dumped[fat.total_size()], &fat.end_marker, sizeof(uint64_t));
        memcpy(&dumped[sizeof(uint64_t)], fat.raw(), fat.total_size());
        // now we should recreate new fs from this dump and check
        lofat::fs fat_ref(fs_cluster_size, fs_cluster_count, fs_filename_max_length, dumped.data() + sizeof(uint64_t), lofat::EFsInitAction::Use);
        const uint32_t file_count = fat_ref.file_count();
        for (uint32_t i = 0; i < file_count; i++) {
            lofat::fileinfo fi = fat_ref.stat(filenames[i].c_str());
            int32_t fd = fat_ref.open(filenames[i].c_str(), 'r');
            std::vector<uint8_t> data(fi.props->size);
            fat_ref.read(data.data(), 1, fi.props->size, fd);
            uint32_t recrc = update_crc32_ccit(data.data(), fi.props->size, CRC32_DEFAULT_VALUE);
            assert(recrc == crcs[i] && recrc == fi.props->crc32);
            fat_ref.close(fd);
            fat_ref.remove(fd);
        }
        uint32_t sys_used_mem = fat_ref.total_size() - fat_ref.free_available_mem_size();
        uint32_t sys_used_mem_ref = fat_ref.system_used_clusters() * fat_ref.cluster_size();
        assert(sys_used_mem == sys_used_mem_ref);
        for (uint32_t i = 0; i < file_count; i++) {
            fat.remove(filenames[i].c_str());
        }
        uint32_t sys_used_mem0 = (uint32_t)fat.total_size() - fat.free_available_mem_size();
        uint32_t sys_used_mem_ref0 = fat.system_used_clusters() * fat.cluster_size();
        assert(sys_used_mem0 == sys_used_mem_ref0);
        //
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        cycle_idx++;
    }
    printf("File system dump test performed %u times\n", cycle_idx);
}

int main()
{  
    srand((uint32_t)time(nullptr));
    test_randomized_rw(240.0f);
    test_randomized_dump(240.0f);
    return 0;
}
