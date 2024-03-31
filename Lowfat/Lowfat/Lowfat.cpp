// Lowfat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <inttypes.h>
#include <memory>
#include <cstring>

#define LF_FILE_OK                     0

#define LF_FILE_LOCKED                 1
#define LF_FILE_READ                   2
#define LF_FILE_WRITE                  4

#define LF_FILE_ERROR_NOT_FOUND       -1
#define LF_FILE_ERROR_ALREADY_OPENED  -2
#define LF_FILE_ERROR_TABLE_ENDED     -3
#define LF_FILE_ERROR_NAME_NULL       -4
#define LF_FILE_ERROR_NAME_TOO_LONG   -5
#define LF_FILE_ERROR_WRONG_MODE      -6
#define LF_FILE_ERROR_SPACE_ENDED     -7

#define LF_CLUSTER_ERROR_NOT_FOUND    -1

namespace lowfat {
#pragma pack(push, 1)
    template<int32_t NAME_LENGTH=32>
    struct fileinfo {
        char name[NAME_LENGTH] = { '\0' };
        uint32_t size = 0;
        int32_t start_cluster = -1;
        int32_t last_cluster = -1;
        uint32_t locked = 0;
        uint32_t current_cluster = 0;
        uint32_t current_byte = 0;

        void reset() {
            memset(name, '\0', NAME_LENGTH * sizeof(char));
            size = 0;
            start_cluster = -1;
            last_cluster = -1;
            locked = 0;
            current_cluster = 0;
            current_byte = 0;
        }
    };
    template<uint32_t TOTAL_SIZE=8192*1024,
             uint32_t CLUSTER_SIZE=8192, 
             uint32_t NAME_LENGTH=32> // 8 MiB total, 8 KiB cluster, 31 char for name + \0
    class fs {
    public:
        fs() {
            this->reset();
        }
        int32_t open(const char* filename, char mode) {
            if (filename == nullptr) {
                return LF_FILE_ERROR_NAME_NULL;
            }
            size_t filename_len = strlen(filename);
            if (filename_len > NAME_LENGTH - 1) {
                return LF_FILE_ERROR_NAME_TOO_LONG;
            }
            int32_t _current_busy_head = _filename_table_busy_head;
            while (_current_busy_head != LF_FILE_ERROR_NOT_FOUND) {
                if (strcmp(_fileinfos[_current_busy_head].name, filename) == 0) {
                    if ((_fileinfos[_current_busy_head].locked & LF_FILE_LOCKED) == 0) {
                        _fileinfos[_current_busy_head].locked |= LF_FILE_LOCKED;
                    }
                    else {
                        _current_busy_head = LF_FILE_ERROR_ALREADY_OPENED; // already locked
                    }
                    break;
                }
                _current_busy_head = _filename_table[_current_busy_head];
            }
            if (mode == 'r') {
                if (_current_busy_head >= 0) {
                    _fileinfos[_current_busy_head].locked |= LF_FILE_READ;
                }
                return _current_busy_head;
            }
            else if (mode == 'w') {
                if (_current_busy_head >= 0) {
                    // overwrite
                    _fileinfos[_current_busy_head].locked |= LF_FILE_WRITE;
                    return _current_busy_head;
                }
                else {
                    if (_current_busy_head == LF_FILE_ERROR_ALREADY_OPENED) {
                        return LF_FILE_ERROR_ALREADY_OPENED;
                    }
                    if (_data_table_free_head == -1) {
                        return LF_FILE_ERROR_SPACE_ENDED;
                    }
                    // LF_FILE_ERROR_NOT_FOUND - create new
                    if (_filename_table_free_head != -1) {
                        _current_busy_head = _filename_table_free_head;
                        _filename_table_free_head = _filename_table[_filename_table_free_head];
                        _filename_table[_current_busy_head] = _filename_table_busy_head;
                        _filename_table_busy_head = _current_busy_head;
                        // put busy node to the head of list
                        int32_t _data_current_busy_head = _data_table_free_head;
                        _data_table_free_head = _data_table[_data_table_free_head];
                        _data_table[_data_current_busy_head] = _data_table_busy_head;
                        _data_table_busy_head = _data_current_busy_head;
                        // add to _fileinfos first free start_cluster
                        sprintf_s(_fileinfos[_current_busy_head].name, NAME_LENGTH, filename);
                        _fileinfos[_current_busy_head].locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                        _fileinfos[_current_busy_head].start_cluster = _data_table_busy_head;
                        _fileinfos[_current_busy_head].last_cluster = _data_table_busy_head;
                        _fileinfos[_current_busy_head].size = 0;
                        _fileinfos[_current_busy_head].current_cluster = 0;
                        _fileinfos[_current_busy_head].current_byte = 0;
                        return _current_busy_head;
                    }
                    else {
                        // not opened for overwriting and no empty space to create new
                        return LF_FILE_ERROR_TABLE_ENDED;
                    }
                }
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
            int32_t total_write_size = elem_size * count;
            while (total_write_size > 0) {
                int32_t mem_can_write = CLUSTER_SIZE - _fileinfos[fd].current_byte;
                if (mem_can_write == 0) {
                    // go to the next cluster
                    if (_data_table_free_head == LF_CLUSTER_ERROR_NOT_FOUND) {
                        return LF_FILE_ERROR_SPACE_ENDED;
                    }
                    _data_table[_fileinfos[fd].last_cluster] = _data_table_free_head;
                    _fileinfos[fd].last_cluster = _data_table_free_head;
                    _data_table_free_head = _data_table[_data_table_free_head];
                }
                if (mem_can_write >= total_write_size) {
                    mem_can_write = total_write_size;
                }
                memcpy(_data[_fileinfos[fd].last_cluster * CLUSTER_SIZE + _fileinfos[fd].current_byte], buf, mem_can_write);
                _fileinfos[fd].current_byte += mem_can_write;
                total_write_size -= mem_can_write;
            }
            return LF_FILE_OK;
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                _fileinfos[fd].locked = 0;
                _fileinfos[fd].current_cluster = _fileinfos[fd].start_cluster;
                _fileinfos[fd].current_byte = 0;
                return LF_FILE_OK;
            }
            return fd;
        }
        int32_t remove(const char* filename) {
            int32_t prev_busy_head = LF_FILE_ERROR_NOT_FOUND;
            int32_t current_busy_head = _filename_table_busy_head;
            while (current_busy_head != LF_FILE_ERROR_NOT_FOUND) {
                if (strcmp(_fileinfos[current_busy_head].name, filename) == 0) {
                    if ((_fileinfos[current_busy_head].locked & LF_FILE_LOCKED) == 0) {
                        // remove file clusters from busy, update data fat
                        int32_t start_cluster = _fileinfos[current_busy_head].start_cluster;
                        int32_t last_cluster = _fileinfos[current_busy_head].last_cluster;

                        int32_t prev_data_busy_head = LF_CLUSTER_ERROR_NOT_FOUND;
                        int32_t current_data_busy_head = _data_table_busy_head;

                        while (current_data_busy_head != LF_CLUSTER_ERROR_NOT_FOUND) {
                            if (current_data_busy_head == start_cluster) {
                                if (prev_data_busy_head != LF_CLUSTER_ERROR_NOT_FOUND) {
                                    _data_table[prev_data_busy_head] = _data_table[last_cluster];
                                }
                                else {
                                    _data_table_busy_head = _data_table[last_cluster];
                                }
                                _data_table[last_cluster] = _data_table_free_head;
                                _data_table_free_head = start_cluster;
                                break;
                            }
                            prev_data_busy_head = current_data_busy_head;
                            current_data_busy_head = _data_table[current_data_busy_head];
                        }
                        if (current_data_busy_head == LF_CLUSTER_ERROR_NOT_FOUND) {
                            return LF_CLUSTER_ERROR_NOT_FOUND;
                        }
                        //
                        _fileinfos[current_busy_head].reset();
                        if (prev_busy_head != LF_FILE_ERROR_NOT_FOUND) {
                            _filename_table[prev_busy_head] = _filename_table[current_busy_head];
                        }
                        else {
                            _filename_table_busy_head = _filename_table[current_busy_head];
                        }
                        _filename_table[current_busy_head] = _filename_table_free_head;
                        _filename_table_free_head = current_busy_head;
                        //
                        return LF_FILE_OK;
                    }
                    else {
                        return LF_FILE_ERROR_ALREADY_OPENED;
                    }
                }
                prev_busy_head = current_busy_head;
                current_busy_head = _filename_table[current_busy_head];
            }
            return LF_FILE_ERROR_NOT_FOUND;
        }
    private:
        static constexpr uint32_t CLUSTER_COUNT = TOTAL_SIZE / CLUSTER_SIZE;
        fileinfo<NAME_LENGTH> _fileinfos[CLUSTER_COUNT] = {};
        int32_t _filename_table[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_busy_head = LF_FILE_ERROR_NOT_FOUND;
        int32_t _filename_table_free_head = 0;
        // HERE IS HOW DATA BEHAVES
        uint8_t _data[TOTAL_SIZE] = { 0 };
        int32_t _data_table[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_busy_head = LF_CLUSTER_ERROR_NOT_FOUND;
        int32_t _data_table_free_head = 0;
        //
        void reset() {
            for (int i = 0; i < CLUSTER_COUNT; i++) {
                _fileinfos[i].reset();
                _filename_table[i] = i + 1;
                _data_table[i] = i + 1;
            }
            _filename_table[CLUSTER_COUNT - 1] = LF_FILE_ERROR_NOT_FOUND;
            _filename_table_busy_head = LF_FILE_ERROR_NOT_FOUND;
            _filename_table_free_head = 0;

            _data_table[CLUSTER_COUNT - 1] = LF_CLUSTER_ERROR_NOT_FOUND;
            _data_table_busy_head = LF_CLUSTER_ERROR_NOT_FOUND;
            _data_table_free_head = 0;
        }
    };
#pragma pack(pop)
}

int main()
{
    const uint32_t fs_size = 64 * 1024;
    const uint32_t fs_cluster_size = 8 * 1024;
    const uint32_t fs_filename_max_length = 32;
    std::unique_ptr<lowfat::fs<fs_size, fs_cluster_size, fs_filename_max_length>> fat_test_ptr = std::make_unique<lowfat::fs<fs_size, fs_cluster_size, fs_filename_max_length>>();
    for (int i = 0; i < 8; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat_test_ptr->open(filename, 'w');
        int32_t close_res = fat_test_ptr->close(test);
    }
    for (int i = 0; i < 8; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t remove_res = fat_test_ptr->remove(filename);
    }
    for (int i = 0; i < 8; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = fat_test_ptr->open(filename, 'w');
        int32_t close_res = fat_test_ptr->close(test);
    }
    for (int i = 5; i < 13; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i % (fs_size / fs_cluster_size));
        int32_t remove_res = fat_test_ptr->remove(filename);
    }
    return 0;
}
