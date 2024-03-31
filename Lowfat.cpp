// Lowfat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <inttypes.h>
#include <memory>
#include <cstring>

#define LF_FILE_OK               0

#define LF_FILE_LOCKED           1
#define LF_FILE_READ             2
#define LF_FILE_WRITE            4

#define LF_FILE_NOT_FOUND       -1
#define LF_FILE_ALREADY_OPENED  -2
#define LF_FILE_TABLE_ENDED     -3
#define LF_FILE_NAME_NULL       -4
#define LF_FILE_NAME_TOO_LONG   -5

namespace lowfat {
#pragma pack(push, 1)
    template<int32_t NAME_LENGTH=32>
    struct fileinfo {
        char name[NAME_LENGTH] = { '\0' };
        uint32_t byte_size = 0;
        int32_t start_cluster = -1;
        uint32_t locked = 0;

        void reset() {
            memset(name, '\0', NAME_LENGTH * sizeof(char));
            start_cluster = -1;
            locked = 0;
            byte_size = 0;
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
                return LF_FILE_NAME_NULL;
            }
            int32_t filename_len = strlen(filename);
            if (filename_len > NAME_LENGTH - 1) {
                return LF_FILE_NAME_TOO_LONG;
            }
            int32_t _current_busy_head = _filename_table_busy_head;
            while (_current_busy_head != LF_FILE_NOT_FOUND) {
                if (strcmp(_fileinfos[_current_busy_head].name, filename) == 0) {
                    if ((_fileinfos[_current_busy_head].locked & LF_FILE_LOCKED) == 0) {
                        _fileinfos[_current_busy_head].locked |= LF_FILE_LOCKED;
                    }
                    else {
                        _current_busy_head = LF_FILE_ALREADY_OPENED; // already locked
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
                    if (_current_busy_head == LF_FILE_ALREADY_OPENED) {
                        return LF_FILE_ALREADY_OPENED;
                    }
                    // LF_FILE_NOT_FOUND - create new
                    if (_filename_table_free_head != -1) {
                        _current_busy_head = _filename_table_free_head;
                        sprintf_s(_fileinfos[_current_busy_head].name, NAME_LENGTH, filename);
                        _fileinfos[_current_busy_head].locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                        // put busy node to the head of list
                        _filename_table_free_head = _filename_table[_filename_table_free_head];
                        _filename_table[_current_busy_head] = _filename_table_busy_head;
                        _filename_table_busy_head = _current_busy_head;
                        // add to _fileinfos first free start_cluster
                        return _current_busy_head;
                    }
                    else {
                        // not opened for overwriting and no empty space to create new
                        return LF_FILE_TABLE_ENDED;
                    }
                }
            }
        }
        int32_t read(int32_t fd, uint8_t* buf, uint32_t stride, uint32_t count) {
            return -1;
        }
        int32_t write(int32_t fd, uint8_t* buf, uint32_t count) {
            return -1;
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                _fileinfos[fd].locked = 0;
                return LF_FILE_OK;
            }
            return fd;
        }
        int32_t remove(const char* filename) {
            int32_t _prev_busy_head = LF_FILE_NOT_FOUND;
            int32_t _current_busy_head = _filename_table_busy_head;
            while (_current_busy_head != LF_FILE_NOT_FOUND) {
                if (strcmp(_fileinfos[_current_busy_head].name, filename) == 0) {
                    if ((_fileinfos[_current_busy_head].locked & LF_FILE_LOCKED) == 0) {
                        // remove file clusters from busy, update data fat
                        // TODO
                        _fileinfos[_current_busy_head].reset();
                        if (_prev_busy_head != LF_FILE_NOT_FOUND) {
                            _filename_table[_prev_busy_head] = _filename_table[_current_busy_head];
                        }
                        else {
                            _filename_table_busy_head = _filename_table[_current_busy_head];
                        }
                        _filename_table[_current_busy_head] = _filename_table_free_head;
                        _filename_table_free_head = _current_busy_head;
                        //
                        return LF_FILE_OK;
                    }
                    else {
                        return LF_FILE_ALREADY_OPENED;
                    }
                }
                _prev_busy_head = _current_busy_head;
                _current_busy_head = _filename_table[_current_busy_head];
            }
            return LF_FILE_NOT_FOUND;
        }
    private:
        static constexpr uint32_t CLUSTER_COUNT = TOTAL_SIZE / CLUSTER_SIZE;
        fileinfo<NAME_LENGTH> _fileinfos[CLUSTER_COUNT] = {};
        int32_t _filename_table[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_busy_head = -1;
        int32_t _filename_table_free_head = 0;
        // HERE IS HOW DATA BEHAVES
        uint8_t _data[TOTAL_SIZE] = {};
        int32_t _data_table[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_busy_head = -1;
        int32_t _data_table_free_head = 0;
        //
        void reset() {
            for (int i = 0; i < CLUSTER_COUNT; i++) {
                _fileinfos[i].reset();
                _filename_table[i] = i + 1;
            }
            _filename_table[CLUSTER_COUNT - 1] = -1;
            _filename_table_busy_head = -1;
            _filename_table_free_head = 0;
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

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
