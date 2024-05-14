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
    struct fileprops {
        uint32_t size = 0;
        int32_t first_cluster = -1;
        int32_t last_cluster = -1;
        uint32_t locked = 0;
        uint32_t current_cluster = 0;
        uint32_t current_byte = 0;
        uint64_t mtime = 0;
        uint32_t crc32 = CRC32_DEFAULT_VALUE;
        //
        uint32_t reserved[4];
    };

    struct fileinfo {
        std::vector<char> name;
        uint32_t name_length = 0;
        fileprops props;

        fileinfo(uint32_t _name_length) : name_length(_name_length) {
            name.resize(name_length);
            std::fill(name.begin(), name.end(), '\0');
        }

        void reset() {
            assert(name_length > 0);
            std::fill(name.begin(), name.end(), '\0');
            props.size = 0;
            props.first_cluster = LF_NONE;
            props.last_cluster = LF_NONE;
            props.locked = 0;
            props.current_cluster = LF_NONE;
            props.current_byte = 0;
            props.mtime = 0;
            props.crc32 = CRC32_DEFAULT_VALUE;
        }

        uint32_t type_size() const {
            // packed tight
            return sizeof(fileprops) + name.size() + 4;
        }
    };
    struct fsinfo_t {
        uint32_t cluster_size;
        uint32_t cluster_count;
        uint32_t name_max_length;
        uint32_t file_count;
        uint32_t filename_busy_head;
        uint32_t filename_free_head;
        uint32_t data_busy_tail;
        uint32_t data_free_head;
        //
        uint32_t reserved[16];
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
            return name.size();
        }
    };

    class fs {
    public:
        const uint32_t cluster_size;
        const uint32_t cluster_count;
        const uint32_t filename_length;
        const uint32_t total_size;
        const uint32_t filename_table_size;
        const uint32_t data_table_size;
        const uint32_t filesystem_info_size;
        const uint32_t system_used_size;
        const uint32_t system_used_clusters;
        const uint32_t last_system_cluster;
        
        fs(uint32_t _cluster_size, uint32_t _cluster_count, uint32_t _filename_length) : 
            cluster_size(_cluster_size), 
            cluster_count(_cluster_count), 
            filename_length(_filename_length),
            total_size(_cluster_size * _cluster_count),
            filename_table_size(cluster_count * sizeof(int32_t) * 2),   // next + prev
            data_table_size(cluster_count * sizeof(int32_t) * 2),       // next + prev
            filesystem_info_size(cluster_count * fileinfo(_filename_length).type_size()),
            system_used_size(sizeof(fsinfo_t) + filesystem_info_size + filename_table_size + data_table_size),
            system_used_clusters(system_used_size / _cluster_count),
            last_system_cluster(system_used_clusters - 1),
            _used_memory(system_used_size),
            _used_cluster_count(system_used_clusters)
        {
            assert(system_used_clusters < cluster_count);
            for (int i = 0; i < cluster_count; i++) {
                _fileinfos.push_back(fileinfo(filename_length));
            }
            _data_table_next.resize(cluster_count);
            _data_table_prev.resize(cluster_count);
            _filename_table_next.resize(cluster_count);
            _filename_table_prev.resize(cluster_count);
            _data.resize(total_size, 0);
            this->reset();
        }
        void prepare_to_dump() {
            uint32_t offset = 0;
            fsinfo_t fsinfo { cluster_size, cluster_count, filename_length, _file_count,
                _filename_table_busy_tail, _filename_table_free_head,
                _data_table_busy_tail, _data_table_free_head };
            memcpy(_data.data(), &fsinfo, sizeof(fsinfo_t));
            offset += sizeof(fsinfo_t);
            const uint32_t fileinfo_array_size = cluster_count * fileinfo(filename_length).type_size();
            memcpy(&_data[offset], &_fileinfos, fileinfo_array_size);
            offset += fileinfo_array_size;
            memcpy(&_data[offset], _filename_table_next.data(), filename_table_size / 2);
            offset += filename_table_size / 2;
            memcpy(&_data[offset], _filename_table_prev.data(), filename_table_size / 2);
            offset += filename_table_size / 2;
            memcpy(&_data[offset], _data_table_next.data(), data_table_size / 2);
            offset += data_table_size / 2;
            memcpy(&_data[offset], _data_table_prev.data(), data_table_size / 2);
            offset += data_table_size / 2;
            assert(offset == system_used_size);
        }
        int32_t open(const char* filename, char mode) {
            if (filename == nullptr) {
                return LF_ERROR_FILE_NAME_NULL;
            }
            size_t filename_len = strlen(filename);
            if (filename_len > filename_length - 1) {
                return LF_ERROR_FILE_NAME_TOO_LONG;
            }
            int32_t fd = this->find(filename);
            if (fd >= 0 && fd < system_used_clusters) {
                return LF_ERROR_SYSTEM_SECTION;
            }
            if (mode == 'r') {
                if (fd >= 0) {
                    _fileinfos[fd].props.locked |= LF_FILE_READ;
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
                acquire_next_free(_filename_table_next.data(), _filename_table_prev.data(), _filename_table_busy_tail, _filename_table_free_head);
                fd = _filename_table_busy_tail;
                // put busy node to the head of list
                acquire_next_free(_data_table_next.data(), _data_table_prev.data(), _data_table_busy_tail, _data_table_free_head);
                _used_cluster_count++;
                // add to _fileinfos first free first_cluster
                sprintf_s(_fileinfos[fd].name.data(), filename_length, filename);
                _fileinfos[fd].props.locked = (LF_FILE_LOCKED | LF_FILE_WRITE);
                _fileinfos[fd].props.first_cluster = _data_table_busy_tail;
                _fileinfos[fd].props.last_cluster = _data_table_busy_tail;
                _fileinfos[fd].props.size = 0;
                _fileinfos[fd].props.current_cluster = _data_table_busy_tail;
                _fileinfos[fd].props.current_byte = 0;
                _fileinfos[fd].props.mtime = 0;
                _file_count++;
                return fd;
            }
            return LF_ERROR_FILE_WRONG_MODE;
        }
        int32_t read(uint8_t* buf, uint32_t elem_size, uint32_t count, int32_t fd) {
            if (fd >= 0 && fd < system_used_clusters) {
                return LF_ERROR_SYSTEM_SECTION;
            }
            if (fd > last_system_cluster) {
                fileinfo& fdi = _fileinfos[fd];
                uint32_t read_size = elem_size * count;
                if (read_size > fdi.props.size) {
                    return LF_ERROR_FILE_READ_SIZE_OVERFLOW;
                }
                uint32_t buf_offset = 0;
                while (read_size > 0) {
                    uint32_t mem_can_read = cluster_size - _fileinfos[fd].props.current_byte;
                    if (mem_can_read == 0) {
                        _fileinfos[fd].props.current_cluster = _data_table_next[_fileinfos[fd].props.current_cluster];
                        _fileinfos[fd].props.current_byte = 0;
                        mem_can_read = cluster_size;
                    }
                    if (mem_can_read > read_size) {
                        mem_can_read = read_size;
                    }
                    //
                    uint32_t offset = _fileinfos[fd].props.current_cluster * cluster_size + _fileinfos[fd].props.current_byte;
                    memcpy(buf + buf_offset, &_data[offset], mem_can_read);
                    //
                    _fileinfos[fd].props.current_byte += mem_can_read;
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
                int32_t mem_can_write = cluster_size - _fileinfos[fd].props.current_byte;
                if (mem_can_write == 0) {
                    // go to the next cluster
                    assert(_data_table_free_head != LF_NONE);
                    if (_data_table_free_head == LF_NONE) {
                        return LF_ERROR_SPACE_ENDED;
                    }
                    acquire_next_free(_data_table_next.data(), _data_table_prev.data(), _data_table_busy_tail, _data_table_free_head);
                    _fileinfos[fd].props.last_cluster = _data_table_busy_tail;
                    _fileinfos[fd].props.current_byte = 0;
                    mem_can_write = cluster_size;
                    _used_cluster_count++;
                }
                if (mem_can_write >= total_write_size) {
                    mem_can_write = total_write_size;
                }
                uint32_t offset = _fileinfos[fd].props.last_cluster * cluster_size + _fileinfos[fd].props.current_byte;
                //
                memcpy(&_data[offset], buf + buf_offset, mem_can_write);
                //
                _fileinfos[fd].props.current_byte += mem_can_write;
                _fileinfos[fd].props.size += mem_can_write;
                buf_offset += mem_can_write;
                total_write_size -= mem_can_write;
            }
            _fileinfos[fd].props.crc32 = s_crc32.update(buf, elem_size * count, _fileinfos[fd].props.crc32);
            _used_memory += elem_size * count;
            return count;
        }
        int32_t close(int32_t fd) {
            if (fd >= 0) {
                _fileinfos[fd].props.locked = 0;
                _fileinfos[fd].props.current_cluster = _fileinfos[fd].props.first_cluster;
                _fileinfos[fd].props.current_byte = 0;
                assert(_fileinfos[fd].props.size != 0);
#if _DEBUG
                printf("Close descriptor %d of size %u and crc32 = %u\n", fd, _fileinfos[fd].props.size, _fileinfos[fd].props.crc32);
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
            int32_t busy_head = _filename_table_next[last_system_cluster];
            while (busy_head != LF_NONE) {
                if (strcmp(_fileinfos[busy_head].name.data(), filename) == 0) {
                    return busy_head;
                }
                busy_head = _filename_table_next[busy_head];
            }
            return LF_ERROR_FILE_NOT_FOUND;
        }

        const fileinfo& stat(int32_t fd) const {
            return _fileinfos[fd];
        }

        fileinfo stat(const char* name) const {
            int fd = find(name);
            if (fd != LF_ERROR_FILE_NOT_FOUND) {
                return _fileinfos[fd];
            }
            const fileinfo empty(filename_length);
            return empty;
        }

        size_t free_mem_size() {
            // real free space, that includes unused clusters memory
            return total_size - _used_memory;
        }

        size_t free_available_mem_size() {
            // real writable amount of memory
            return (cluster_count - _used_cluster_count) * cluster_size;
        }

        int32_t remove(int fd) {
            // busy clusters handle
            int32_t first_cluster = _fileinfos[fd].props.first_cluster;
            int32_t last_cluster = _fileinfos[fd].props.last_cluster;
            uint32_t freed_clusters = calculate_range_length(_data_table_next.data(), first_cluster, last_cluster);
            _used_cluster_count -= freed_clusters;
            free_busy_range(_data_table_next.data(), _data_table_prev.data(), first_cluster, last_cluster, _data_table_busy_tail, _data_table_free_head);
            // 
            free_busy_range(_filename_table_next.data(), _filename_table_prev.data(), fd, fd, _filename_table_busy_tail, _filename_table_free_head);
            // reset properties
            _used_memory -= _fileinfos[fd].props.size;
#if _DEBUG
            printf("Remove file '%s' of size %u\n", _fileinfos[fd].name.data(), _fileinfos[fd].props.size);
#endif
            _fileinfos[fd].reset();
            _file_count--;
            return freed_clusters;
        }

        uint32_t file_count() const {
            return _file_count;
        }
    private:
        std::vector<fileinfo> _fileinfos;
        std::vector<int32_t> _filename_table_next;
        std::vector<int32_t> _filename_table_prev;
        int32_t _filename_table_busy_tail = LF_NONE;
        int32_t _filename_table_free_head = 0;
        uint32_t _file_count = 0;
        // HERE IS HOW DATA BEHAVES
        std::vector<uint8_t> _data; // total_size
        std::vector<int32_t> _data_table_next;
        std::vector<int32_t> _data_table_prev;
        int32_t _data_table_busy_tail = LF_NONE;
        int32_t _data_table_free_head = 0;
        //
        uint32_t _used_memory;
        uint32_t _used_cluster_count;
        //
        void reset() {
            for (int i = 0; i < cluster_count; i++) {
                _fileinfos[i] = fileinfo(filename_length);
                _filename_table_next[i] = i + 1;
                _filename_table_prev[i] = i - 1;
                _data_table_next[i] = i + 1;
                _data_table_prev[i] = i - 1;
            }
            _filename_table_next[cluster_count - 1] = LF_NONE;
            _filename_table_busy_tail = last_system_cluster;
            _filename_table_free_head = last_system_cluster + 1;
            _filename_table_next[_filename_table_busy_tail] = LF_NONE;
            _filename_table_prev[_filename_table_free_head] = LF_NONE;

            for (int i = 0; i < system_used_clusters; i++) {
                snprintf(_fileinfos[i].name.data(), filename_length, "SYSTEM%d", i);
                _fileinfos[i].props.size = cluster_size;
            }

            _data_table_next[cluster_count - 1] = LF_NONE;
            _data_table_busy_tail = last_system_cluster;
            _data_table_free_head = last_system_cluster + 1;
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

void test_fs_readback(lofat::fs& filesys, double test_period) {
    srand(time(nullptr));
    uint32_t file_idx = 0;
    std::vector<lofat::filename_t> filenames;
    std::vector<uint32_t> crcs;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    const std::chrono::duration<double> elapsed_seconds{ end - start };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    uint32_t cycle_idx = 0;
    uint32_t writes_count = 0;
    MemAmount_t rewritten_memory{};
    
    while (elapsed.count() < test_period) {
        size_t available = filesys.free_available_mem_size(); // not tight, free clusters * cluster_size
        if (available) {
            // have a place to write
            size_t random_filesize = (rand() % filesys.total_size) % (available - filesys.cluster_size / 4) + filesys.cluster_size / 4;
            if (cur_empty_file_idx == crcs.size()) {
                // push_back new one
                crcs.push_back(0);
                filenames.push_back(lofat::filename_t(filesys.filename_length));
            }
            std::vector<byte> mem(random_filesize);
            crcs[cur_empty_file_idx] = fill_random_byte_buffer_and_calc_crc32(mem);
            lofat::filename_t& filename = filenames[cur_empty_file_idx];
            snprintf(filename.data(), filename.size(), "test_file_%u_%u.bin", cycle_idx, cur_empty_file_idx);
            int32_t fd = filesys.open(filename.data(), 'w');
            uint32_t written = filesys.write(mem.data(), mem.size(), 1, fd);
            filesys.close(fd);
            assert(written == 1);
            lofat::fileinfo finfo = filesys.stat(fd);
            assert(crcs[cur_empty_file_idx] == finfo.props.crc32);
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
                std::vector<byte> mem(finfo.props.size);
                int32_t read = filesys.read(mem.data(), 1, mem.size(), fd);
                filesys.close(fd);
                uint32_t test_crc32 = lofat::s_crc32.update(mem.data(), mem.size(), CRC32_DEFAULT_VALUE);
                assert(test_crc32 == crcs[cur_file_idx] && test_crc32 == finfo.props.crc32);
                uint32_t freed_clusters = filesys.remove(fd);
                assert(freed_clusters == (mem.size() / filesys.cluster_size + (mem.size() % filesys.cluster_size > 0)));
                //
#if _DEBUG
                printf("Removed '%s'\n", filenames[cur_file_idx].data());
#endif
                if (cur_file_idx != files_written - 1) {
                    assert(strcmp(filenames[cur_file_idx].data(), filenames[cur_empty_file_idx - 1].data()) != 0);
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    crcs[cur_file_idx] = crcs[files_written - 1];
                }
                filenames[files_written - 1] = lofat::filename_t(filesys.filename_length);
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
        std::vector<byte> mem(finfo.props.size);
        int32_t read = filesys.read(mem.data(), 1, mem.size(), fd);
        filesys.close(fd);
        uint32_t test_crc32 = lofat::s_crc32.update(mem.data(), mem.size(), CRC32_DEFAULT_VALUE);
        assert(test_crc32 == crcs[i] && test_crc32 == finfo.props.crc32);
        uint32_t freed_clusters = filesys.remove(fd);
        assert(freed_clusters == (mem.size() / filesys.cluster_size + (mem.size() % filesys.cluster_size > 0)));
    }
    uint32_t mem_busy = filesys.cluster_count * filesys.cluster_size - filesys.free_mem_size();
    assert(mem_busy == filesys.system_used_size);
    printf("File system randomized RW test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, filesys.total_size);
}

void test_crc32() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length);
    //
    const char test_abc[] = "ABC";
    const char test_d[] = "D";
    uint32_t crc_test_3 = lofat::s_crc32.update((uint8_t*)test_abc, 3, CRC32_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = lofat::s_crc32.update((uint8_t*)test_d, 1, crc_test_3);
    printf("ABCD remainder lookuped: %#010x\n", crc_test_3);
    {
        int32_t abc_fd = fat.open("saved_text.txt", 'w');
        fat.write((uint8_t*)test_abc, 3, 1, abc_fd);
        fat.write((uint8_t*)test_d, 1, 1, abc_fd);
        fat.close(abc_fd);
        const lofat::fileinfo& fst = fat.stat(abc_fd);
        printf("File remainder lookuped: %#010x\n", fst.props.crc32);
    }
}

void test_simple_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length);

    const int max_user_file_count = fat.cluster_count - fat.system_used_clusters;
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
        char* text = new char[file_info.props.size];
        fat.read((uint8_t*)text, 1, file_info.props.size, text_fd);
        fat.close(text_fd);
        delete[] text;
    }
}

void test_randomized_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    lofat::fs fat(fs_cluster_size, fs_cluster_count, fs_filename_max_length);

    test_fs_readback(fat, 240.0f);
}

int main()
{
    test_randomized_rw();
    return 0;
}
