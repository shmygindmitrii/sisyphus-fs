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

#include "crc32_ccit.h"
#include "lowfat.h"

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

namespace lofat {
#pragma pack(push, 1)
    struct fileprops {
        uint64_t mtime = 0;
        uint32_t size = 0;
        uint32_t crc32 = CRC32_CCIT_DEFAULT_VALUE;
        int32_t first_cluster = -1;
        int32_t last_cluster = -1;
        int32_t current_cluster = 0;   // not more than 65536 clusters
        uint16_t current_byte = 0;     // not more than 65536 bytes in cluster
        uint8_t locked = 0;

        void reset() {
            mtime = 0;
            size = 0;
            crc32 = CRC32_CCIT_DEFAULT_VALUE;
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
                fi.props->crc32 = crc32_ccit_update(buf, elem_size * count, fi.props->crc32);
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
            assert(fd >= 0 && fd < (int32_t)*_cluster_count);
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
    return crc32_ccit_update(mem.data(), (uint32_t)mem.size(), CRC32_CCIT_DEFAULT_VALUE);
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
                uint32_t test_crc32 = crc32_ccit_update(mem.data(), (uint32_t)mem.size(), CRC32_CCIT_DEFAULT_VALUE);
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
        uint32_t test_crc32 = crc32_ccit_update(mem.data(), (uint32_t)mem.size(), CRC32_CCIT_DEFAULT_VALUE);
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
    uint32_t crc_test_3 = crc32_ccit_update((uint8_t*)test_abc, 3, CRC32_CCIT_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = crc32_ccit_update((uint8_t*)test_d, 1, crc_test_3);
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
        memcpy(&dumped[sizeof(uint64_t) + fat.total_size()], &fat.end_marker, sizeof(uint64_t));
        memcpy(&dumped[sizeof(uint64_t)], fat.raw(), fat.total_size());
        // now we should recreate new fs from this dump and check
        std::vector<uint8_t> redumped; // to fill from file
        FILE* dumpfile = nullptr;
        fopen_s(&dumpfile, "test.fs", "wb");
        if (dumpfile) {
            size_t written = fwrite(dumped.data(), dumped.size(), 1, dumpfile);
            assert(written == 1ULL);
            fclose(dumpfile);
            dumpfile = nullptr;
            fopen_s(&dumpfile, "test.fs", "rb");
            if (dumpfile) {
                fseek(dumpfile, 0, SEEK_END);
                uint32_t filesize = ftell(dumpfile);
                fseek(dumpfile, 0, SEEK_SET);
                assert(filesize == (uint32_t)dumped.size());
                redumped.resize(filesize, 0);
                fread(redumped.data(), filesize, 1, dumpfile);
                fclose(dumpfile);
            }
        }
        assert(redumped.size() == dumped.size());
        uint64_t start_val = *((uint64_t*)redumped.data());
        uint64_t end_val = *((uint64_t*)(redumped.data() + fat.total_size() + sizeof(uint64_t)));
        assert(start_val == lofat::fs::start_marker && end_val == lofat::fs::end_marker);
        lofat::fs fat_ref(fs_cluster_size, fs_cluster_count, fs_filename_max_length, redumped.data() + sizeof(uint64_t), lofat::EFsInitAction::Use);
        const uint32_t file_count = fat_ref.file_count();
        for (uint32_t i = 0; i < file_count; i++) {
            lofat::fileinfo fi = fat_ref.stat(filenames[i].c_str());
            int32_t fd = fat_ref.open(filenames[i].c_str(), 'r');
            std::vector<uint8_t> data(fi.props->size);
            fat_ref.read(data.data(), 1, fi.props->size, fd);
            uint32_t recrc = crc32_ccit_update(data.data(), fi.props->size, CRC32_CCIT_DEFAULT_VALUE);
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
    printf("File system randomized dump test finished: %u cycles of fullfilling and working over dumped fs\n", cycle_idx);
}

extern "C" {
    int main()
    {
        srand((uint32_t)time(nullptr));
        //test_randomized_rw(240.0f);
        test_randomized_dump(10.0f);
        return 0;
    }
}
