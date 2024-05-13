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
    static constexpr uint32_t CRC_CCIT32 = 0x04C11DB7;
    static constexpr uint32_t CRC_CCIT32_REV = 0xEDB88320;

    template<uint32_t P>
    struct crc32 {
        crc32() {
            for (uint32_t i = 0; i < 256; i++) {
                uint32_t cur = i;
                for (uint32_t j = 0; j < 8; j++) {
                    cur = (cur & 1) ? ((cur >> 1) ^ P) : (cur >> 1);
                }
                table[i] = cur;
            }
        }
        uint32_t update(uint8_t* data, uint32_t size, uint32_t crc) const {
            for (uint32_t i = 0; i < size; i++) {
                crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFF;
        }
    private:
        uint32_t table[256] = { 0 };
    };

    static const crc32<CRC_CCIT32_REV> s_crc32;

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
        uint32_t crc32 = CRC32_DEFAULT_VALUE;
        //
        uint32_t reserved[8];

        void reset() {
            memset(name, '\0', NAME_LENGTH * sizeof(char));
            size = 0;
            first_cluster = LF_NONE;
            last_cluster = LF_NONE;
            locked = 0;
            current_cluster = LF_NONE;
            current_byte = 0;
            mtime = 0;
            crc32 = CRC32_DEFAULT_VALUE;
        }
    };
    struct fsinfo_t {
        uint32_t total_size;
        uint32_t cluster_size;
        uint32_t name_max_length;
        uint32_t file_count;
        uint32_t filename_busy_head;
        uint32_t filename_free_head;
        uint32_t data_busy_tail;
        uint32_t data_free_head;
        //
        uint32_t reserved[25];
    };
    template<uint32_t _TOTAL_SIZE,
             uint32_t _CLUSTER_SIZE,
             uint32_t _NAME_LENGTH>
    class fs {
    public:
        struct filename_t {
            static constexpr uint32_t size = _NAME_LENGTH;
            char name[size + 1] = { 0 };

            char* data() {
                return &name[0];
            }
        };
        static constexpr uint32_t TOTAL_SIZE = _TOTAL_SIZE;
        static constexpr uint32_t CLUSTER_SIZE = _CLUSTER_SIZE;
        static constexpr uint32_t NAME_LENGTH = _NAME_LENGTH;
        static constexpr uint32_t CLUSTER_COUNT = TOTAL_SIZE / CLUSTER_SIZE;
        static constexpr uint32_t FS_INFO_SIZE = sizeof(fsinfo_t);
        static constexpr uint32_t FILEINFO_ARRAY_SIZE = CLUSTER_COUNT * sizeof(fileinfo<NAME_LENGTH>);
        static constexpr uint32_t FILENAME_TABLE_SIZE = CLUSTER_COUNT * sizeof(int32_t) * 2; // next + prev
        static constexpr uint32_t DATA_TABLE_SIZE = CLUSTER_COUNT * sizeof(int32_t) * 2; // next + prev
        static constexpr uint32_t SYSTEM_USED_SIZE = FS_INFO_SIZE + FILEINFO_ARRAY_SIZE + FILENAME_TABLE_SIZE + DATA_TABLE_SIZE;
        static constexpr uint32_t SYSTEM_USED_CLUSTERS = SYSTEM_USED_SIZE / CLUSTER_SIZE + ((SYSTEM_USED_SIZE % CLUSTER_SIZE) > 0);
        static constexpr uint32_t LAST_SYSTEM_CLUSTER = SYSTEM_USED_CLUSTERS - 1;
        static_assert(SYSTEM_USED_CLUSTERS < CLUSTER_COUNT);
        fs() {
            this->reset();
        }
        void prepare_to_dump() {
            uint32_t offset = 0;
            fsinfo_t fsinfo { TOTAL_SIZE, CLUSTER_SIZE, NAME_LENGTH, _file_count,
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
                return LF_ERROR_FILE_NAME_NULL;
            }
            size_t filename_len = strlen(filename);
            if (filename_len > NAME_LENGTH - 1) {
                return LF_ERROR_FILE_NAME_TOO_LONG;
            }
            int32_t fd = this->find(filename);
            if (fd >= 0 && fd < SYSTEM_USED_CLUSTERS) {
                return LF_ERROR_SYSTEM_SECTION;
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
                    fd = LF_ERROR_FILE_NOT_FOUND;
                }
                if (fd == LF_ERROR_FILE_ALREADY_OPENED) {
                    return LF_ERROR_FILE_ALREADY_OPENED;
                }
                if (_data_table_free_head == LF_NONE) {
                    return LF_ERROR_SPACE_ENDED;
                }
                assert(fd == LF_ERROR_FILE_NOT_FOUND);
                // LF_FILE_ERROR_NOT_FOUND - create new
                acquire_next_free(_filename_table_next, _filename_table_prev, _filename_table_busy_tail, _filename_table_free_head);
                fd = _filename_table_busy_tail;
                // put busy node to the head of list
                acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                _used_cluster_count++;
                // add to _fileinfos first free first_cluster
                sprintf_s(_fileinfos[fd].name, NAME_LENGTH, filename);
                _fileinfos[fd].locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                _fileinfos[fd].first_cluster = _data_table_busy_tail;
                _fileinfos[fd].last_cluster = _data_table_busy_tail;
                _fileinfos[fd].size = 0;
                _fileinfos[fd].current_cluster = _data_table_busy_tail;
                _fileinfos[fd].current_byte = 0;
                _fileinfos[fd].mtime = 0;
                _file_count++;
                return fd;
            }
            return LF_ERROR_FILE_WRONG_MODE;
        }
        int32_t read(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
            if (fd >= 0 && fd < SYSTEM_USED_CLUSTERS) {
                return LF_ERROR_SYSTEM_SECTION;
            }
            if (fd > LAST_SYSTEM_CLUSTER) {
                fileinfo<NAME_LENGTH>& fdi = _fileinfos[fd];
                uint32_t read_size = elem_size * count;
                if (read_size > fdi.size) {
                    return LF_ERROR_FILE_READ_SIZE_OVERFLOW;
                }
                uint32_t buf_offset = 0;
                while (read_size > 0) {
                    uint32_t mem_can_read = CLUSTER_SIZE - _fileinfos[fd].current_byte;
                    if (mem_can_read == 0) {
                        _fileinfos[fd].current_cluster = _data_table_next[_fileinfos[fd].current_cluster];
                        _fileinfos[fd].current_byte = 0;
                        mem_can_read = CLUSTER_SIZE;
                    }
                    if (mem_can_read > read_size) {
                        mem_can_read = read_size;
                    }
                    //
                    uint32_t offset = _fileinfos[fd].current_cluster * CLUSTER_SIZE + _fileinfos[fd].current_byte;
                    memcpy(buf + buf_offset, &_data[offset], mem_can_read);
                    //
                    _fileinfos[fd].current_byte += mem_can_read;
                    buf_offset += mem_can_read;
                    read_size -= mem_can_read;
                }
                return LF_OK;
            }
            return LF_ERROR_FILE_NOT_FOUND;
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
                        return LF_ERROR_SPACE_ENDED;
                    }
                    acquire_next_free(_data_table_next, _data_table_prev, _data_table_busy_tail, _data_table_free_head);
                    _fileinfos[fd].last_cluster = _data_table_busy_tail;
                    _fileinfos[fd].current_byte = 0;
                    mem_can_write = CLUSTER_SIZE;
                    _used_cluster_count++;
                }
                if (mem_can_write >= total_write_size) {
                    mem_can_write = total_write_size;
                }
                uint32_t offset = _fileinfos[fd].last_cluster * CLUSTER_SIZE + _fileinfos[fd].current_byte;
                //
                memcpy(&_data[offset], buf + buf_offset, mem_can_write);
                //
                _fileinfos[fd].current_byte += mem_can_write;
                _fileinfos[fd].size += mem_can_write;
                buf_offset += mem_can_write;
                total_write_size -= mem_can_write;
            }
            _fileinfos[fd].crc32 = s_crc32.update(buf, elem_size * count, _fileinfos[fd].crc32);
            _used_memory += elem_size * count;
            return count;
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                _fileinfos[fd].locked = 0;
                _fileinfos[fd].current_cluster = _fileinfos[fd].first_cluster;
                _fileinfos[fd].current_byte = 0;
                assert(_fileinfos[fd].size != 0);
#if _DEBUG
                printf("Close descriptor %d of size %u and crc32 = %u\n", fd, _fileinfos[fd].size, _fileinfos[fd].crc32);
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

        int32_t find(const char* filename) {
            // linear search
            int32_t busy_head = _filename_table_next[LAST_SYSTEM_CLUSTER];
            while (busy_head != LF_NONE) {
                if (strcmp(_fileinfos[busy_head].name, filename) == 0) {
                    return busy_head;
                }
                busy_head = _filename_table_next[busy_head];
            }
            return LF_ERROR_FILE_NOT_FOUND;
        }

        fileinfo<NAME_LENGTH> stat(int32_t fd) {
            return _fileinfos[fd];
        }

        fileinfo<NAME_LENGTH> stat(const char* name) {
            int fd = find(name);
            if (fd != LF_ERROR_FILE_NOT_FOUND) {
                return _fileinfos[fd];
            }
            fileinfo<NAME_LENGTH> empty;
            return empty;
        }

        size_t free_mem_size() {
            // real free space, that includes unused clusters memory
            return TOTAL_SIZE - _used_memory;
        }

        size_t free_available_mem_size() {
            // real writable amount of memory
            return (CLUSTER_COUNT - _used_cluster_count) * CLUSTER_SIZE;
        }

        int32_t remove(int fd) {
            // busy clusters handle
            int32_t first_cluster = _fileinfos[fd].first_cluster;
            int32_t last_cluster = _fileinfos[fd].last_cluster;
            uint32_t freed_clusters = calculate_range_length(_data_table_next, first_cluster, last_cluster);
            _used_cluster_count -= freed_clusters;
            free_busy_range(_data_table_next, _data_table_prev, first_cluster, last_cluster, _data_table_busy_tail, _data_table_free_head);
            // 
            free_busy_range(_filename_table_next, _filename_table_prev, fd, fd, _filename_table_busy_tail, _filename_table_free_head);
            // reset properties
            _used_memory -= _fileinfos[fd].size;
#if _DEBUG
            printf("Remove file '%s' of size %u\n", _fileinfos[fd].name, _fileinfos[fd].size);
#endif
            _fileinfos[fd].reset();
            _file_count--;
            return freed_clusters;
        }

        uint32_t file_count() const {
            return _file_count;
        }
    private:
        fileinfo<NAME_LENGTH> _fileinfos[CLUSTER_COUNT] = {};
        int32_t _filename_table_next[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_prev[CLUSTER_COUNT] = { 0 };
        int32_t _filename_table_busy_tail = LF_NONE;
        int32_t _filename_table_free_head = 0;
        uint32_t _file_count = 0;
        // HERE IS HOW DATA BEHAVES
        uint8_t _data[TOTAL_SIZE] = { 0 };
        int32_t _data_table_next[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_prev[CLUSTER_COUNT] = { 0 };
        int32_t _data_table_busy_tail = LF_NONE;
        int32_t _data_table_free_head = 0;
        //
        uint32_t _used_memory = SYSTEM_USED_SIZE;
        uint32_t _used_cluster_count = SYSTEM_USED_CLUSTERS;
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
    };
#pragma pack(pop)
}

uint32_t fill_random_byte_buffer_and_calc_crc32(std::vector<byte>& mem) {
    for (int i = 0; i < mem.size(); i++) {
        mem[i] = (uint8_t)(rand() % 256);
    }
    return lofat::s_crc32.update(mem.data(), mem.size(), CRC32_DEFAULT_VALUE);
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

template<uint32_t TOTAL_SIZE,
         uint32_t CLUSTER_SIZE,
         uint32_t NAME_LENGTH>
void test_fs_readback(lofat::fs<TOTAL_SIZE, CLUSTER_SIZE, NAME_LENGTH>& filesys, double test_period) {
    using fsclass = typename lofat::fs<TOTAL_SIZE, CLUSTER_SIZE, NAME_LENGTH>;
    using filename_t = typename lofat::fs<TOTAL_SIZE, CLUSTER_SIZE, NAME_LENGTH>::filename_t;
    using fileinfo_t = typename lofat::fileinfo<NAME_LENGTH>;
    srand(time(nullptr));
    uint32_t file_idx = 0;
    std::vector<filename_t> filenames;
    std::vector<uint32_t> crcs;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    const std::chrono::duration<double> elapsed_seconds{ end - start };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    uint32_t cycle_idx = 0;
    uint32_t writes_count = 0;
    MemAmount_t rewritten_memory{};
    //uint32_t 
    while (elapsed.count() < test_period) {
        size_t available = filesys.free_available_mem_size(); // not tight, free clusters * cluster_size
        if (available) {
            // have a place to write
            size_t random_filesize = (rand() % TOTAL_SIZE) % (available - CLUSTER_SIZE / 4) + CLUSTER_SIZE / 4;
            if (cur_empty_file_idx == crcs.size()) {
                // push_back new one
                crcs.push_back(0);
                filenames.push_back(filename_t{});
            }
            std::vector<byte> mem(random_filesize);
            crcs[cur_empty_file_idx] = fill_random_byte_buffer_and_calc_crc32(mem);
            filename_t& filename = filenames[cur_empty_file_idx];
            snprintf(filename.data(), filename.size, "test_file_%u_%u.bin", cycle_idx, cur_empty_file_idx);
            int32_t fd = filesys.open(filename.data(), 'w');
            uint32_t written = filesys.write(mem.data(), mem.size(), 1, fd);
            filesys.close(fd);
            assert(written == 1);
            fileinfo_t finfo = filesys.stat(fd);
            assert(crcs[cur_empty_file_idx] == finfo.crc32);
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
                fileinfo_t finfo = filesys.stat(fd);
                std::vector<byte> mem(finfo.size);
                int32_t read = filesys.read(mem.data(), 1, mem.size(), fd);
                filesys.close(fd);
                uint32_t test_crc32 = lofat::s_crc32.update(mem.data(), mem.size(), CRC32_DEFAULT_VALUE);
                assert(test_crc32 == crcs[cur_file_idx] && test_crc32 == finfo.crc32);
                uint32_t freed_clusters = filesys.remove(fd);
                assert(freed_clusters == (mem.size() / CLUSTER_SIZE + (mem.size() % CLUSTER_SIZE > 0)));
                //
#if _DEBUG
                printf("Removed '%s'\n", filenames[cur_file_idx].data());
#endif
                if (cur_file_idx != files_written - 1) {
                    assert(strcmp(filenames[cur_file_idx].data(), filenames[cur_empty_file_idx - 1].data()) != 0);
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    crcs[cur_file_idx] = crcs[files_written - 1];
                }
                filenames[files_written - 1] = {};
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
        fileinfo_t finfo = filesys.stat(fd);
        std::vector<byte> mem(finfo.size);
        int32_t read = filesys.read(mem.data(), 1, mem.size(), fd);
        filesys.close(fd);
        uint32_t test_crc32 = lofat::s_crc32.update(mem.data(), mem.size(), CRC32_DEFAULT_VALUE);
        assert(test_crc32 == crcs[i] && test_crc32 == finfo.crc32);
        uint32_t freed_clusters = filesys.remove(fd);
        assert(freed_clusters == (mem.size() / CLUSTER_SIZE + (mem.size() % CLUSTER_SIZE > 0)));
    }
    uint32_t mem_busy = filesys.CLUSTER_COUNT * filesys.CLUSTER_SIZE - filesys.free_mem_size();
    assert(mem_busy == filesys.SYSTEM_USED_SIZE);
    printf("File system randomized RW test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, TOTAL_SIZE);
}

void test_crc32() {
    const uint32_t fs_cluster_size = 1024;
    const uint32_t fs_size = 32 * fs_cluster_size;
    const uint32_t fs_filename_max_length = 32;
    std::unique_ptr<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>> fat_test_ptr = std::make_unique<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>>();
    //
    const char test_abc[] = "ABC";
    const char test_d[] = "D";
    uint32_t crc_test_3 = lofat::s_crc32.update((uint8_t*)test_abc, 3, CRC32_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = lofat::s_crc32.update((uint8_t*)test_d, 1, crc_test_3);
    printf("ABCD remainder lookuped: %#010x\n", crc_test_3);
    {
        int32_t abc_fd = fat_test_ptr->open("saved_text.txt", 'w');
        fat_test_ptr->write((uint8_t*)test_abc, 3, 1, abc_fd);
        fat_test_ptr->write((uint8_t*)test_d, 1, 1, abc_fd);
        fat_test_ptr->close(abc_fd);
        lofat::fileinfo<fs_filename_max_length> fst = fat_test_ptr->stat(abc_fd);
        printf("File remainder lookuped: %#010x\n", fst.crc32);
    }
}

void test_simple_rw() {
    const uint32_t fs_cluster_size = 1024;
    const uint32_t fs_size = 32 * fs_cluster_size;
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
        uint8_t test_buf[fs_cluster_size / 2] = { 0 };
        memset(test_buf, 2, fs_cluster_size / 2);
        fat_test_ptr->write(test_buf, 1, fs_cluster_size / 2, test_fd);
        int32_t close_res = fat_test_ptr->close(test_fd);
    }
    {
        char text[1536] = { '\0' };
        int32_t switcher = 1536 / ('z' - 'a' + 1);
        for (int i = 0; i < 1536; i++) {
            text[i] = 'a' + i / switcher;
        }
        int32_t text_fd = fat_test_ptr->open("saved_text.txt", 'w');
        fat_test_ptr->write((uint8_t*)(text), 1, sizeof(text), text_fd);
        fat_test_ptr->close(text_fd);
    }
    {
        int32_t text_fd = fat_test_ptr->open("saved_text.txt", 'r');
        lofat::fileinfo<fs_filename_max_length> file_info = fat_test_ptr->stat(text_fd);
        char* text = new char[file_info.size];
        fat_test_ptr->read((uint8_t*)text, 1, file_info.size, text_fd);
        fat_test_ptr->close(text_fd);
        delete[] text;
    }
}

void test_randomized_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_size = 1024 * fs_cluster_size;
    const uint32_t fs_filename_max_length = 32;
    std::unique_ptr<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>> fat_test_ptr = std::make_unique<lofat::fs<fs_size, fs_cluster_size, fs_filename_max_length>>();

    test_fs_readback(*fat_test_ptr, 240.0f);
}

int main()
{
    test_randomized_rw();
    return 0;
}
