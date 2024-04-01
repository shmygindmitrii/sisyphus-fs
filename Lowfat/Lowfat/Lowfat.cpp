// Lowfat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <vector>
//
#include <iostream>
#include <inttypes.h>
#include <memory>
#include <cstring>
#include <cassert>

#define LF_FILE_OK                     0

#define LF_FILE_LOCKED                 1
#define LF_FILE_READ                   2
#define LF_FILE_WRITE                  4

#define LF_FILE_ERROR_NOT_FOUND       -2
#define LF_FILE_ERROR_ALREADY_OPENED  -3
#define LF_FILE_ERROR_TABLE_ENDED     -4
#define LF_FILE_ERROR_NAME_NULL       -5
#define LF_FILE_ERROR_NAME_TOO_LONG   -6
#define LF_FILE_ERROR_WRONG_MODE      -7
#define LF_FILE_ERROR_SPACE_ENDED     -8
#define LF_FILE_ERROR_SYSTEM_SECTION  -9

#define LF_NONE                       -1

// tail addition
static inline void acquire_next_free(int32_t* table_next, int32_t* table_prev, int32_t& last_busy, int32_t& first_free) {
    int32_t cur_free = first_free;
    assert(table_prev[cur_free] == LF_NONE);
    first_free = table_next[first_free];
    if (first_free != LF_NONE) {
        table_prev[first_free] = LF_NONE;
    }
    assert(table_next[last_busy] == LF_NONE);
    table_prev[cur_free] = last_busy;
    table_next[last_busy] = cur_free;
    table_next[cur_free] = LF_NONE;
    last_busy = cur_free;
}

static inline void free_busy_range(int32_t* table_next, int32_t* table_prev, int32_t first, int32_t last, int32_t& last_busy, int32_t& first_free) {
    // merge busy list segments
    int32_t prev = table_prev[first];
    int32_t next = table_next[last];
    table_next[prev] = next; // never LF_NONE, because of system used nodes
    if (next != LF_NONE) {
        table_prev[next] = prev;
    }
    else {
        last_busy = prev;
    }
    // detach from busy chain and attach to free one in the beginning
    table_prev[first] = LF_NONE;
    table_next[last] = first_free;
    if (first_free != LF_NONE) {
        assert(table_prev[first_free] == LF_NONE);
        table_prev[first_free] = last;
    }
    first_free = first;
}

namespace lofat {
#pragma pack(push, 1)
    template<int32_t NAME_LENGTH>
    struct fileinfo {
        char name[NAME_LENGTH] = { '\0' };
        uint32_t size = 0;
        int32_t first_cluster = -1;
        int32_t last_cluster = -1;
        uint32_t locked = 0;
        uint32_t current_cluster = 0;
        uint32_t current_byte = 0;
        uint64_t mtime = 0;

        void reset() {
            memset(name, '\0', NAME_LENGTH * sizeof(char));
            size = 0;
            first_cluster = LF_NONE;
            last_cluster = LF_NONE;
            locked = 0;
            current_cluster = LF_NONE;
            current_byte = 0;
        }
    };
    struct fsinfo_t {
        uint32_t total_size;
        uint32_t cluster_size;
        uint32_t name_max_length;
        uint32_t filename_busy_head;
        uint32_t filename_free_head;
        uint32_t data_busy_tail;
        uint32_t data_free_head;
        //
        uint32_t reserved[25];
    };
    template<uint32_t TOTAL_SIZE,
             uint32_t CLUSTER_SIZE,
             uint32_t NAME_LENGTH>
    class fs {
    public:
        static constexpr uint32_t CLUSTER_COUNT = TOTAL_SIZE / CLUSTER_SIZE;
        static constexpr uint32_t FS_INFO_SIZE = sizeof(fsinfo_t);
        static constexpr uint32_t FILEINFO_ARRAY_SIZE = CLUSTER_COUNT * sizeof(fileinfo<NAME_LENGTH>);
        static constexpr uint32_t FILENAME_TABLE_SIZE = CLUSTER_COUNT * sizeof(int32_t) * 2; // next + prev
        static constexpr uint32_t DATA_TABLE_SIZE = CLUSTER_COUNT * sizeof(int32_t) * 2; // next + prev
        static constexpr uint32_t SYSTEM_USED_SIZE = FS_INFO_SIZE + FILEINFO_ARRAY_SIZE + FILENAME_TABLE_SIZE + DATA_TABLE_SIZE;
        static constexpr uint32_t SYSTEM_USED_CLUSTERS = SYSTEM_USED_SIZE / CLUSTER_SIZE + ((SYSTEM_USED_SIZE % CLUSTER_SIZE) > 0);
        static constexpr uint32_t LAST_SYSTEM_CLUSTER = SYSTEM_USED_CLUSTERS - 1;
        fs() {
            this->reset();
        }
        void prepare_to_dump() {
            uint32_t offset = 0;
            fsinfo_t fsinfo { TOTAL_SIZE, CLUSTER_SIZE, NAME_LENGTH, 
                _filename_table_busy_tail, _filename_table_free_head,
                _data_table_busy_tail, _data_table_free_head };
            memcpy(_data, &fsinfo, FS_INFO_SIZE);
            offset += FS_INFO_SIZE;
            memcpy(_data + offset, &_fileinfos, FILEINFO_ARRAY_SIZE);
            offset += FILEINFO_ARRAY_SIZE;
            memcpy(_data + offset, _filename_table_next, FILENAME_TABLE_SIZE / 2);
            offset += FILENAME_TABLE_SIZE / 2;
            memcpy(_data + offset, _filename_table_prev, FILENAME_TABLE_SIZE / 2);
            offset += FILENAME_TABLE_SIZE / 2;
            memcpy(_data + offset, _data_table_next, DATA_TABLE_SIZE / 2);
            offset += DATA_TABLE_SIZE / 2;
            memcpy(_data + offset, _data_table_prev, DATA_TABLE_SIZE / 2);
            offset += DATA_TABLE_SIZE / 2;
            assert(offset == SYSTEM_USED_SIZE);
        }
        int32_t open(const char* filename, char mode) {
            if (filename == nullptr) {
                return LF_FILE_ERROR_NAME_NULL;
            }
            size_t filename_len = strlen(filename);
            if (filename_len > NAME_LENGTH - 1) {
                return LF_FILE_ERROR_NAME_TOO_LONG;
            }
            int32_t fd = this->find(filename);
            if (fd >= 0 && fd < SYSTEM_USED_CLUSTERS) {
                return LF_FILE_ERROR_SYSTEM_SECTION;
            }
            if (mode == 'r') {
                if (fd >= 0) {
                    _fileinfos[fd].locked |= LF_FILE_READ;
                }
                return fd;
            }
            else if (mode == 'w') {
                if (fd >= 0) {
                    // remove existing
                    this->remove(fd);
                    fd = LF_FILE_ERROR_NOT_FOUND;
                }
                if (fd == LF_FILE_ERROR_ALREADY_OPENED) {
                    return LF_FILE_ERROR_ALREADY_OPENED;
                }
                if (_data_table_free_head == LF_NONE) {
                    return LF_FILE_ERROR_SPACE_ENDED;
                }
                assert(fd == LF_FILE_ERROR_NOT_FOUND);
                // LF_FILE_ERROR_NOT_FOUND - create new
                acquire_next_free(_filename_table_next, _filename_table_prev, _filename_table_busy_tail, _filename_table_free_head);
                fd = _filename_table_busy_tail;
                // put busy node to the head of list
                acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                // add to _fileinfos first free first_cluster
                sprintf_s(_fileinfos[fd].name, NAME_LENGTH, filename);
                _fileinfos[fd].locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                _fileinfos[fd].first_cluster = _data_table_busy_tail;
                _fileinfos[fd].last_cluster = _data_table_busy_tail;
                _fileinfos[fd].size = 0;
                _fileinfos[fd].current_cluster = _data_table_busy_tail;
                _fileinfos[fd].current_byte = 0;
                _fileinfos[fd].mtime = 0;
                return fd;
            }
            return LF_FILE_ERROR_WRONG_MODE;
        }
        int32_t read(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
#if 0
            int32_t cluster_count = _fileinfos[fd].size / CLUSTER_SIZE + static_cast<int>((_fileinfos[fd].size % CLUSTER_SIZE) > 0);
            int32_t remain_size = _fileinfos[fd].size;
            for (int i = 0; i < cluster_count; i++) {
                // TODO
                remain_size -= CLUSTER_SIZE;
            }
#endif
            return -1;
        }
        int32_t write(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
            // always write new
            int32_t total_write_size = elem_size * count;
            uint32_t buf_offset = 0;
            while (total_write_size > 0) {
                int32_t mem_can_write = CLUSTER_SIZE - _fileinfos[fd].current_byte;
                if (mem_can_write == 0) {
                    // go to the next cluster
                    assert(_data_table_free_head != LF_NONE);
                    if (_data_table_free_head == LF_NONE) {
                        return LF_FILE_ERROR_SPACE_ENDED;
                    }
                    acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                    _fileinfos[fd].last_cluster = _data_table_busy_tail;
                    _fileinfos[fd].current_byte = 0;
                    mem_can_write = CLUSTER_SIZE;
                }
                if (mem_can_write >= total_write_size) {
                    mem_can_write = total_write_size;
                }
                uint32_t offset = _fileinfos[fd].last_cluster * CLUSTER_SIZE + _fileinfos[fd].current_byte;
                memcpy(_data + offset, buf + buf_offset, mem_can_write);
                _fileinfos[fd].current_byte += mem_can_write;
                _fileinfos[fd].size += mem_can_write;
                buf_offset += mem_can_write;
                total_write_size -= mem_can_write;
            }
            return elem_size * count;
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                _fileinfos[fd].locked = 0;
                _fileinfos[fd].current_cluster = _fileinfos[fd].first_cluster;
                _fileinfos[fd].current_byte = 0;
                return LF_FILE_OK;
            }
            return fd;
        }
        
        int32_t remove(const char* filename) {
            int32_t fd = this->find(filename);
            if (fd >= LF_FILE_OK) {
                return this->remove(fd);
            }
            return fd;
        }
    private:
        fileinfo<NAME_LENGTH> _fileinfos[CLUSTER_COUNT] = {};
        int32_t _filename_table_next[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_prev[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_busy_tail = LF_NONE;
        int32_t _filename_table_free_head = 0;
        // HERE IS HOW DATA BEHAVES
        uint8_t _data[TOTAL_SIZE] = { 0 };
        int32_t _data_table_next[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_prev[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_busy_tail = LF_NONE;
        int32_t _data_table_free_head = 0;
        //
        void reset() {
            for (int i = 0; i < CLUSTER_COUNT; i++) {
                _fileinfos[i].reset();
                _filename_table_next[i] = i + 1;
                _filename_table_prev[i] = i - 1;
                _data_table_next[i] = i + 1;
                _data_table_prev[i] = i - 1;
            }
            _filename_table_next[CLUSTER_COUNT - 1] = LF_NONE;
            _filename_table_busy_tail = LAST_SYSTEM_CLUSTER;
            _filename_table_free_head = LAST_SYSTEM_CLUSTER + 1;
            _filename_table_next[_filename_table_busy_tail] = LF_NONE;
            _filename_table_prev[_filename_table_free_head] = LF_NONE;

            for (int i = 0; i < SYSTEM_USED_CLUSTERS; i++) {
                snprintf(_fileinfos[i].name, NAME_LENGTH, "SYSTEM%d", i);
                _fileinfos[i].size = CLUSTER_SIZE;
            }

            _data_table_next[CLUSTER_COUNT - 1] = LF_NONE;
            _data_table_busy_tail = LAST_SYSTEM_CLUSTER;
            _data_table_free_head = LAST_SYSTEM_CLUSTER + 1;
            _data_table_next[_data_table_busy_tail] = LF_NONE;
            _data_table_prev[_data_table_free_head] = LF_NONE;
        }
        int32_t find(const char* filename) {
            // linear search
            int32_t busy_head = _filename_table_next[LAST_SYSTEM_CLUSTER];
            while (busy_head != LF_NONE) {
                if (strcmp(_fileinfos[busy_head].name, filename) == 0) {
                    return busy_head;
                }
                busy_head = _filename_table_next[busy_head];
            }
            return LF_FILE_ERROR_NOT_FOUND;
        }
        int32_t remove(int fd) {
            // busy clusters handle
            int32_t first_cluster = _fileinfos[fd].first_cluster;
            int32_t last_cluster = _fileinfos[fd].last_cluster;
            free_busy_range(_data_table_next, _data_table_prev, first_cluster, last_cluster, _data_table_busy_tail, _data_table_free_head);
            // 
            free_busy_range(_filename_table_next, _filename_table_prev, fd, fd, _filename_table_busy_tail, _filename_table_free_head);
            // reset properties
            _fileinfos[fd].reset();
            return LF_FILE_OK;
        }
    };
#pragma pack(pop)
}

int main()
{
    const uint32_t fs_cluster_size = 256;
    const uint32_t fs_size = 8 * fs_cluster_size;
    const uint32_t fs_filename_max_length = 32;
    std::unique_ptr<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>> fat_test_ptr = std::make_unique<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>>();
    const int max_user_file_count = fat_test_ptr->CLUSTER_COUNT - fat_test_ptr->SYSTEM_USED_CLUSTERS;
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat_test_ptr->open(filename, 'w');
        assert(test >= 0);
        int32_t close_res = fat_test_ptr->close(test);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t remove_res = fat_test_ptr->remove(filename);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat_test_ptr->open(filename, 'w');
        int32_t close_res = fat_test_ptr->close(test);
    }
    for (int i = 5; i < max_user_file_count + 5; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i % max_user_file_count);
        int32_t remove_res = fat_test_ptr->remove(filename);
    }
    {
        int32_t test_fd = fat_test_ptr->open("three.txt", 'w');
        uint8_t test_buf[fs_cluster_size * 3] = { 0 };
        memset(test_buf, 1, fs_cluster_size * 3);
        fat_test_ptr->write(test_buf, 1, fs_cluster_size * 3, test_fd);
        int32_t close_res = fat_test_ptr->close(test_fd);
    }
    {
        int32_t test_fd = fat_test_ptr->open("three_and_half.txt", 'w');
        uint8_t test_buf[fs_cluster_size * 3 + fs_cluster_size / 2] = { 0 };
        memset(test_buf, 2, fs_cluster_size * 3);
        fat_test_ptr->write(test_buf, 1, fs_cluster_size * 3 + fs_cluster_size / 2, test_fd);
        int32_t close_res = fat_test_ptr->close(test_fd);
    }
    // TODO: MASSIVE TESTING OF EVERYTHING
    // NEED A LOT OF RANDOM TESTS WITH CHECKING OF CORRECTNESS OVER MILLIONS OF WRITINGS
    return 0;
}
