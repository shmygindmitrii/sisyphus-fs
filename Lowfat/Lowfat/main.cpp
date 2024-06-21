// Lowfat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <vector>
//
#include <iostream>
#include <inttypes.h>
#include <memory>
#include <string>
#include <cassert>
#include <bitset>
#include <ctime>
#include <chrono>
#include <unordered_map>
#include <type_traits>
#include <variant>
#include <random>
#include <atomic>
#include <cstdlib>

#include "crc32_ccit.h"
#include "lowfat.h"
#include "linkfs.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace {
    template<typename T>
    void maybe_unused(T&&) {}
}

#define MAYBE_UNUSED(x) maybe_unused(x);

static std::unordered_map<intptr_t, size_t> allocated_table = {};
static size_t allocated_total = 0;

class SpinLock_t {
public:
    void lock() {
        while (_flag.test_and_set(std::memory_order_acquire)) {
            // nothing to do, just wait
            // test_and_set sets always to true and return previous value
            // if it is true already, then true is returned and cycle continues
            // until clear sets it to false
        }
    }
    void unlock() { 
        _flag.clear(std::memory_order_release);
    }
private:
    std::atomic_flag _flag = ATOMIC_FLAG_INIT;
};

static SpinLock_t s_allocator_lock;

class SpinLockAllocatorGuard {
public:
    SpinLockAllocatorGuard() {
        s_allocator_lock.lock();
    }
    ~SpinLockAllocatorGuard() {
        s_allocator_lock.unlock();
    }
};

extern "C" {
    void* user_malloc(size_t size) {
        const SpinLockAllocatorGuard G;
        void* ptr = malloc(size);
        allocated_table[(intptr_t)ptr] = size;
        allocated_total += size;
        return ptr;
    }

    void user_free(void* ptr) {
        const SpinLockAllocatorGuard G;
        assert(allocated_table.find((intptr_t)ptr) != allocated_table.end());
        allocated_total -= allocated_table[(intptr_t)ptr];
        allocated_table.erase((intptr_t)ptr);
        free(ptr);
    }
}

enum class EResultType {
    Ok,
    Error
};

template <typename T, EResultType R>
struct ResultValue {
    T value = {};
    static constexpr EResultType type = R;
    ResultValue() = default;
    explicit ResultValue(const T& arg) : value(arg) {}
    explicit ResultValue(T&& arg) noexcept : value(std::move(arg)) {}
};

template<typename O, typename E>
struct Result {
    static_assert(!std::is_convertible_v<O, E>);

    using OkType = typename ResultValue<O, EResultType::Ok>;
    using ErrType = typename ResultValue<E, EResultType::Error>;

    OkType ok;
    ErrType error;
    EResultType type;

    explicit Result(const O& value) : ok(value), type(EResultType::Ok) {}
    explicit Result(O&& value) noexcept : ok(std::move(value)), type(EResultType::Ok) {}
    explicit Result(const E& value) : error(value), type(EResultType::Error) {}
    explicit Result(E&& value) noexcept : error(std::move(value)), type(EResultType::Error) {}

    // non-copyable
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;

    Result(Result&&) noexcept = default;
    Result& operator=(Result&&) noexcept = default;

    bool is_ok() const {
        return type == EResultType::Ok;
    }

    bool is_err() const {
        return type == EResultType::Error;
    }

    const O& unwrap_ok() const {
        assert(type == EResultType::Ok);
        return ok.value;
    }

    const E& unwrap_err() const {
        assert(type == EResultType::Error);
        return error.value;
    }

    operator bool() const {
        return this->is_ok();
    }
};

class RandomUint32Generator {
public:
    RandomUint32Generator() {
        static std::once_flag _init;
        std::call_once(_init, []() {
            RandomUint32Generator::initialize();
        });
    }
    uint32_t operator()() const {
        return INT_MAX + 1U + _dis(_gen);
    }
    static void initialize() {
        std::random_device rd;
        _gen = std::mt19937(rd());
        _dis = std::uniform_int_distribution<>(INT_MIN, INT_MAX);
    }
private:
    static std::mt19937 _gen;
    static std::uniform_int_distribution<> _dis;
};

std::mt19937 RandomUint32Generator::_gen;
std::uniform_int_distribution<> RandomUint32Generator::_dis;

uint32_t fill_random_byte_buffer_and_calc_crc32(std::vector<uint8_t>& mem) {
    RandomUint32Generator rand_gen;
    for (uint32_t i = 0; i < (uint32_t)mem.size(); i++) {
        mem[i] = (uint8_t)(rand_gen() % 256);
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

enum class out_of_space_t {};
static const out_of_space_t out_of_space = {};

struct write_info_t {
    uint32_t filesize = 0;
    uint32_t crc = 0;
    std::string fname = {};
};

Result<write_info_t, out_of_space_t> write_to_lowfat_fs_instance_random_file(lowfat_fs* fs_ptr) {
    static size_t s_call_idx = 0;
    RandomUint32Generator rand_gen;
    size_t available = lowfat_fs_free_available_mem_size(fs_ptr); // not tight, free clusters * cluster_size
    if (available) {
        // have a place to write
        write_info_t wrinfo = {};
        wrinfo.filesize = (uint32_t)((rand_gen() % lowfat_fs_total_size(fs_ptr)) % (available - lowfat_fs_cluster_size(fs_ptr) / 4) + lowfat_fs_cluster_size(fs_ptr) / 4);
        std::vector<uint8_t> mem(wrinfo.filesize);
        wrinfo.crc = fill_random_byte_buffer_and_calc_crc32(mem);
        wrinfo.fname = "test_file_" + std::to_string(s_call_idx++) + ".bin";
#if _DEBUG
        printf("try to save \"%s\" of size %u\n", wrinfo.fname.c_str(), wrinfo.filesize);
#endif
        int32_t fd = lowfat_fs_open_file(fs_ptr, wrinfo.fname.c_str(), 'w');
        uint32_t written = lowfat_fs_write_file(fs_ptr, mem.data(), (uint32_t)mem.size(), 1, fd);
        lowfat_fs_close_file(fs_ptr, fd);
        assert(written == 1);
        lowfat_fs_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
        assert(finfo.name != nullptr);
        assert(wrinfo.crc == finfo.props->crc32);
        return Result<write_info_t, out_of_space_t>(wrinfo);
    }
    return Result<write_info_t, out_of_space_t>(out_of_space);
}

enum class lowfat_fs_wrong_file_count_t {}; 
static const lowfat_fs_wrong_file_count_t lowfat_fs_wrong_file_count = {};

struct lowfat_fs_wrong_file_crc_t {
    uint32_t crc = CRC32_CCIT_DEFAULT_VALUE;
};

enum class lowfat_fs_file_not_found_t {}; 
static const lowfat_fs_file_not_found_t lowfat_fs_file_not_found = {};

struct lowfat_fs_error_t {
    int32_t code = 0;
};

struct lowfat_fs_wrong_file_size_t {
    uint32_t size = 0;
};

struct lowfat_fs_wrong_cluster_count_t {
    uint32_t count = 0;
};

using lowfat_fs_err = std::variant<lowfat_fs_wrong_file_count_t
                                 , lowfat_fs_wrong_file_crc_t
                                 , lowfat_fs_file_not_found_t
                                 , lowfat_fs_error_t
                                 , lowfat_fs_wrong_file_size_t
                                 , lowfat_fs_wrong_cluster_count_t>;

Result<uint32_t, lowfat_fs_err> check_lowfat_fs_single_file(lowfat_fs* fs_ptr, std::string_view filename, uint32_t size, uint32_t crc) {
    // check if exists
    lowfat_fs_fileinfo_t finfo = lowfat_fs_file_stat_str(fs_ptr, filename.data());
    assert(finfo.name != nullptr);
    if (finfo.name == nullptr) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_file_not_found);
    }
    // check file size
    assert(finfo.props->size == size);
    if (finfo.props->size != size) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_wrong_file_size_t{ finfo.props->size });
    }
    // check file content by crc comparison
    // check saved and reference crc first
    assert(finfo.props->crc32 == crc);
    if (finfo.props->crc32 != crc) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_wrong_file_crc_t{ finfo.props->crc32 });
    }
    // recalculate crc to ensure that content is the same
    // read file content
    std::vector<uint8_t> file_content(finfo.props->size, 0);
    int32_t fd = lowfat_fs_open_file(fs_ptr, filename.data(), 'r');
    int32_t read_ret = lowfat_fs_read_file(fs_ptr, file_content.data(), (uint32_t)file_content.size(), 1, fd);
    assert(read_ret == LOWFAT_FS_OK);
    lowfat_fs_close_file(fs_ptr, fd);
    if (read_ret != LOWFAT_FS_OK) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_error_t{ read_ret });
    }
    // file was successfully read, calculate crc32_ccit from its content
    uint32_t crc32_recalculated = crc32_ccit_update(file_content.data(), file_content.size(), CRC32_CCIT_DEFAULT_VALUE);
    assert(crc32_recalculated == crc);
    if (crc32_recalculated != crc) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_wrong_file_crc_t{ crc32_recalculated });
    }
    // if file exists, has the same size and crc is the same - file is ok
    return Result<uint32_t, lowfat_fs_err>(1U);
}

Result<uint32_t, lowfat_fs_err> check_lowfat_fs_files(lowfat_fs* fs_ptr, std::vector<std::string>& filenames, std::vector<uint32_t>& sizes, std::vector<uint32_t>& crcs, uint32_t count) {
    if (fs_ptr->_header->_file_count != count) {
        return Result<uint32_t, lowfat_fs_err>(lowfat_fs_wrong_file_count);
    }
    uint32_t i = 0;
    for (; i < count; i++) {
        const std::string& fname = filenames[i];
        uint32_t ref_crc = crcs[i];
        uint32_t ref_size = sizes[i];
        auto r = check_lowfat_fs_single_file(fs_ptr, fname, ref_size, ref_crc);
        if (r) {
#if _DEBUG
            printf("[lowfat_fs] file checked: %s\n", fname.c_str());
#endif
        }
        else {
            return r;
        }
    }
    assert(i == count);
    Result<uint32_t, lowfat_fs_err> ok(count);
    assert(ok);
    return ok;
}

Result<uint32_t, lowfat_fs_err> remove_lowfat_fs_single_file(lowfat_fs* fs_ptr, std::string_view filename, uint32_t size, uint32_t crc) {
    if (auto res = check_lowfat_fs_single_file(fs_ptr, filename, size, crc)) {
        int32_t fd = lowfat_fs_find_file(fs_ptr, filename.data());
        uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
        // check removed cluster count
        uint32_t cluster_size = lowfat_fs_cluster_size(fs_ptr);
        if (size_t clusters_should_be_freed = size / cluster_size + static_cast<size_t>(size % cluster_size > 0); clusters_should_be_freed != (size_t)freed_clusters) {
            assert(clusters_should_be_freed == (size_t)freed_clusters);
            return Result<uint32_t, lowfat_fs_err>(lowfat_fs_wrong_cluster_count_t{ freed_clusters });
        }
        // file was correct, removed correct cluster count, file deleted successfully
        return Result<uint32_t, lowfat_fs_err>(1U);
    }
    else {
        return res;
    }
}

void test_fs_readback(lowfat_fs* fs_ptr, double test_period) {
    std::vector<std::string> filenames;
    std::vector<uint32_t> sizes;
    std::vector<uint32_t> crcs;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    uint32_t cycle_idx = 0;
    MemAmount_t rewritten_memory{};
    RandomUint32Generator rand_gen;

    while (elapsed.count() < test_period) {
        if (auto wr_res = write_to_lowfat_fs_instance_random_file(fs_ptr)) {
            if (cur_empty_file_idx == (uint32_t)crcs.size()) {
                crcs.emplace_back(wr_res.unwrap_ok().crc);
                filenames.emplace_back(wr_res.unwrap_ok().fname);
                sizes.emplace_back(wr_res.unwrap_ok().filesize);
            }
            else {
                crcs[cur_empty_file_idx] = wr_res.unwrap_ok().crc;
                filenames[cur_empty_file_idx] = wr_res.unwrap_ok().fname;
                sizes[cur_empty_file_idx] = wr_res.unwrap_ok().filesize;
            }
            cur_empty_file_idx++;
            rewritten_memory += wr_res.unwrap_ok().filesize;
        }
        else {
            // need to free place
            uint32_t files_written = lowfat_fs_file_count(fs_ptr);
            uint32_t files_to_remove = (rand_gen() % (files_written - 1)) + 1;
#if _DEBUG
            printf("Space finished, free procedure for %u files of %u \n", files_to_remove, files_written);
#endif
            for (uint32_t i = 0; i < files_to_remove; i++) {
                // need a vector of filenames
                uint32_t cur_file_idx = rand_gen() % files_written;
                auto pre_remove_test_res = check_lowfat_fs_single_file(fs_ptr, filenames[cur_file_idx], sizes[cur_file_idx], crcs[cur_file_idx]);
                assert(pre_remove_test_res.is_ok());
                int32_t fd = lowfat_fs_find_file(fs_ptr, filenames[cur_file_idx].c_str());
                lowfat_fs_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
                uint32_t fsize = finfo.props->size;
                uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
                assert(freed_clusters == (fsize / lowfat_fs_cluster_size(fs_ptr) + (fsize % lowfat_fs_cluster_size(fs_ptr) > 0)));
                if (cur_file_idx != files_written - 1) {
                    assert(filenames[cur_file_idx] != filenames[cur_empty_file_idx - 1]);
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    crcs[cur_file_idx] = crcs[files_written - 1];
                    sizes[cur_file_idx] = sizes[files_written - 1];
                }
                filenames[files_written - 1] = ""; // nullify name
                crcs[files_written - 1] = 0;
                sizes[files_written - 1] = 0;
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
        auto r = check_lowfat_fs_single_file(fs_ptr, filenames[i], sizes[i], crcs[i]);
        assert(r.is_ok());
        int32_t fd = lowfat_fs_find_file(fs_ptr, filenames[i].c_str());
        lowfat_fs_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
        uint32_t fsize = finfo.props->size;
        uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
        assert(freed_clusters == (fsize / lowfat_fs_cluster_size(fs_ptr) + (fsize % lowfat_fs_cluster_size(fs_ptr) > 0)));
    }
    uint32_t mem_busy = lowfat_fs_cluster_count(fs_ptr) * lowfat_fs_cluster_size(fs_ptr) - (uint32_t)lowfat_fs_free_mem_size(fs_ptr);
    assert(mem_busy == lowfat_fs_system_used_size(fs_ptr));
    // do not forget to remove everything
    printf("File system randomized RW test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, lowfat_fs_total_size(fs_ptr));
}

void test_crc32() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data());
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);
    //
    const char test_abc[] = "ABC";
    const char test_d[] = "D";
    uint32_t crc_test_3 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_abc), 3, CRC32_CCIT_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    // https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art008
    assert(crc_test_3 == 0xa3830348);
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_d), 1, crc_test_3);
    printf("ABCD remainder lookuped: %#010x\n", crc_test_3);
    {
        int32_t abc_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'w');
        lowfat_fs_write_file(fs_ptr, reinterpret_cast<const uint8_t*>(test_abc), 3, 1, abc_fd);
        lowfat_fs_write_file(fs_ptr, reinterpret_cast<const uint8_t*>(test_d), 1, 1, abc_fd);
        lowfat_fs_close_file(fs_ptr, abc_fd);
        const lowfat_fs_fileinfo_t fst = lowfat_fs_file_stat(fs_ptr, abc_fd);
        printf("File remainder lookuped: %#010x\n", fst.props->crc32);
    }
    lowfat_fs_destroy_instance(fs_ptr);
}

void test_simple_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data());
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);

    const int max_user_file_count = lowfat_fs_cluster_count(fs_ptr) - lowfat_fs_system_used_clusters(fs_ptr);
    for (int i = 0; i < max_user_file_count; i++) {
        std::string filename = "test" + std::to_string(i) + ".txt";
        int32_t test = lowfat_fs_open_file(fs_ptr, filename.c_str(), 'w');
        assert(test >= 0);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test);
        assert(close_res == LOWFAT_FS_OK);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        std::string filename = "test" + std::to_string(i) + ".txt";
        int32_t remove_res = lowfat_fs_remove_file_str(fs_ptr, filename.c_str());
        assert(remove_res > 0);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        std::string filename = "test" + std::to_string(i) + ".txt";
        int32_t test = lowfat_fs_open_file(fs_ptr, filename.c_str(), 'w');
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test);
        assert(close_res == LOWFAT_FS_OK);
    }
    for (int i = 5; i < max_user_file_count + 5; i++) {
        std::string filename = "test" + std::to_string(i % max_user_file_count) + ".txt";
        int32_t remove_res = lowfat_fs_remove_file_str(fs_ptr, filename.c_str());
        assert(remove_res > 0);
    }
    {
        int32_t test_fd = lowfat_fs_open_file(fs_ptr, "three.txt", 'w');
        std::vector<uint8_t>test_buf(fs_cluster_size * 3);
        memset(test_buf.data(), 1, fs_cluster_size * 3);
        lowfat_fs_write_file(fs_ptr, test_buf.data(), 1, fs_cluster_size * 3, test_fd);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test_fd);
        assert(close_res == LOWFAT_FS_OK);
    }
    {
        int32_t test_fd = lowfat_fs_open_file(fs_ptr, "three_and_half.txt", 'w');
        std::vector<uint8_t>test_buf(fs_cluster_size / 2);
        memset(test_buf.data(), 2, fs_cluster_size / 2);
        lowfat_fs_write_file(fs_ptr, test_buf.data(), 1, fs_cluster_size / 2, test_fd);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test_fd);
        assert(close_res == LOWFAT_FS_OK);
    }
    {
        std::string text;
        text.reserve(1536);
        text.resize(1536);
        int32_t switcher = 1536 / ('z' - 'a' + 1);
        for (int i = 0; i < 1536; i++) {
            text[i] = 'a' + static_cast<char>(i / switcher);
        }
        int32_t text_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'w');
        lowfat_fs_write_file(fs_ptr, reinterpret_cast<const uint8_t*>(text.c_str()), 1, sizeof(text), text_fd);
        lowfat_fs_close_file(fs_ptr, text_fd);
    }
    {
        int32_t text_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'r');
        lowfat_fs_fileinfo_t file_info = lowfat_fs_file_stat(fs_ptr, text_fd);
        auto text = std::make_unique<char[]>(file_info.props->size);
        lowfat_fs_read_file(fs_ptr, (uint8_t*)text.get(), 1, file_info.props->size, text_fd);
        lowfat_fs_close_file(fs_ptr, text_fd);
    }
    lowfat_fs_destroy_instance(fs_ptr);
}

void test_randomized_rw(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data());
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);
    // test begin
    test_fs_readback(fs_ptr, duration);
    // test end
    lowfat_fs_destroy_instance(fs_ptr);
}

void test_randomized_dump(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data());
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);

    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cycle_idx = 0;
    while (elapsed.count() < duration) {
        std::vector<uint32_t> crcs;
        std::vector<uint32_t> sizes;
        std::vector <std::string> filenames;
        while (true) {
            auto wr_res = write_to_lowfat_fs_instance_random_file(fs_ptr);
            if (wr_res.is_err()) {
                break;
            }
            crcs.emplace_back(wr_res.unwrap_ok().crc);
            sizes.emplace_back(wr_res.unwrap_ok().filesize);
            filenames.emplace_back(wr_res.unwrap_ok().fname);
        }
        // finished fullfilling of fs
        std::vector<uint8_t> dumped(lowfat_fs_total_size(fs_ptr), 0);
        memcpy(dumped.data(), fs_mem.data(), lowfat_fs_total_size(fs_ptr));
        // now we should recreate new fs from this dump and check
        std::vector<uint8_t> redumped; // to fill from file
        FILE* dumpfile = nullptr;
        fopen_s(&dumpfile, "test.fs", "wb");
        assert(dumpfile != nullptr);
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

        lowfat_fs* fs_ref_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, redumped.data());
        lowfat_fs_set_instance_addresses(fs_ref_ptr);
        // no reset here, because want to reuse
        check_lowfat_fs_files(fs_ref_ptr, filenames, sizes, crcs, (uint32_t)filenames.size());
        for (const auto& fname: filenames) {
            lowfat_fs_remove_file_str(fs_ptr, fname.c_str());
            lowfat_fs_remove_file_str(fs_ref_ptr, fname.c_str());
        }
        uint32_t sys_used_mem = lowfat_fs_total_size(fs_ptr) - lowfat_fs_free_available_mem_size(fs_ptr);
        uint32_t sys_used_mem_ref = lowfat_fs_system_used_clusters(fs_ptr) * lowfat_fs_cluster_size(fs_ptr);
        assert(sys_used_mem == sys_used_mem_ref);
        uint32_t sys_used_mem0 = lowfat_fs_total_size(fs_ref_ptr) - lowfat_fs_free_available_mem_size(fs_ref_ptr);
        uint32_t sys_used_mem_ref0 = lowfat_fs_system_used_clusters(fs_ref_ptr) * lowfat_fs_cluster_size(fs_ref_ptr);
        assert(sys_used_mem0 == sys_used_mem_ref0);
        //
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        cycle_idx++;
        lowfat_fs_destroy_instance(fs_ref_ptr);
    }
    printf("File system randomized dump test finished: %u cycles of fullfilling and working over dumped fs\n", cycle_idx);
    lowfat_fs_destroy_instance(fs_ptr);
}

static const char s_dumpname[] = "test_fs.bin";
static void* s_fs_start = nullptr;
static size_t s_fs_size = 0;
static size_t rewriter(void* data, size_t size) {
    assert(s_fs_size > 0);
    assert(s_fs_start != nullptr);
    FILE* f = nullptr;
    fopen_s(&f, s_dumpname, "rb");
    static std::vector<uint8_t> mem(s_fs_size, 0);
    if (f) {
        fread(mem.data(), s_fs_size, 1, f);
        fclose(f);
        f = nullptr;
    }
    size_t offset = (char*)data - (char*)s_fs_start;
    assert(offset + size <= s_fs_size);
    memcpy(mem.data() + offset, data, size);
    fopen_s(&f, s_dumpname, "wb");
    if (f) {
        size_t wr = fwrite(mem.data(), s_fs_size, 1, f);
        assert(wr == 1);
        fclose(f);
    }
    return size;
}

lowfat_fs* open_lowfat_fs_from_file(const char* filename) {
    FILE* f = nullptr;
    fopen_s(&f, filename, "rb");
    if (f) {
        struct {
            uint32_t cluster_size;
            uint32_t cluster_count;
            uint32_t filename_length;
        } header;
        fread(&header, sizeof(header), 1, f);
        uint8_t* mem = (uint8_t*)user_malloc(header.cluster_size * header.cluster_count);
        memcpy(mem, &header, sizeof(header));
        fread(mem + sizeof(header), header.cluster_size * header.cluster_count - sizeof(header), 1, f);
        fclose(f);
        lowfat_fs* fs_ptr = lowfat_fs_create_instance(header.cluster_size, header.cluster_count, header.filename_length, mem);
        lowfat_fs_set_instance_addresses(fs_ptr);
        // do not forget to cleanup after
        return fs_ptr;
    }
    return nullptr;
}

void test_randomized_partial_dump(const float duration) {
    MemAmount_t rewritten_memory{};
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data());
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);
    s_fs_size = fs_cluster_count * fs_cluster_size;
    // test begin
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    bool rewritten_once = false;
    std::vector<uint32_t> crcs;
    std::vector<uint32_t> sizes;
    std::vector <std::string> filenames;
    uint32_t check_idx = 0;
    RandomUint32Generator rand_gen;
    while (elapsed.count() < duration) {
        if (Result<write_info_t, out_of_space_t> res = write_to_lowfat_fs_instance_random_file(fs_ptr)) {
            // dumped new
            if (cur_empty_file_idx >= crcs.size()) {
                crcs.emplace_back(res.unwrap_ok().crc);
                filenames.emplace_back(res.unwrap_ok().fname);
                sizes.emplace_back(res.unwrap_ok().filesize);
            }
            else {
                crcs[cur_empty_file_idx] = res.unwrap_ok().crc;
                filenames[cur_empty_file_idx] = std::string(res.unwrap_ok().fname);
                sizes[cur_empty_file_idx] = res.unwrap_ok().filesize;
            }
            cur_empty_file_idx++;
            rewritten_memory += res.unwrap_ok().filesize;
        }
        else {
            // remove random number of files
            // need to free place
            uint32_t files_written = lowfat_fs_file_count(fs_ptr);
            uint32_t files_to_remove = (rand_gen() % (files_written - 1)) + 1;
#if _DEBUG
            printf("Space finished, free procedure for %u files of %u \n", files_to_remove, files_written);
#endif
            for (uint32_t i = 0; i < files_to_remove; i++) {
                // need a vector of filenames
                uint32_t cur_file_idx = rand_gen() % files_written;
                auto remove_res = remove_lowfat_fs_single_file(fs_ptr, filenames[cur_file_idx], sizes[cur_file_idx], crcs[cur_file_idx]);
                assert(remove_res.is_ok());
                if (cur_file_idx != files_written - 1) {
                    assert(filenames[cur_file_idx] != filenames[cur_empty_file_idx - 1]);
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    crcs[cur_file_idx] = crcs[files_written - 1];
                    sizes[cur_file_idx] = sizes[files_written - 1];
                }
                filenames[files_written - 1] = ""; // nullify name
                crcs[files_written - 1] = 0;
                sizes[files_written - 1] = 0;
                files_written--;
            }
            cur_empty_file_idx -= files_to_remove;
        }
        s_fs_start = (void*)fs_ptr->_data;
        lowfat_fs_walk_over_changed_data(fs_ptr, rewriter);
        if (rewritten_once) {
            user_free(fs_ptr->_data);
        }
        lowfat_fs_destroy_instance(fs_ptr);
        fs_ptr = nullptr;
        fs_ptr = open_lowfat_fs_from_file(s_dumpname);
        s_fs_start = (void*)fs_ptr->_data;
        rewritten_once = true;
        assert(cur_empty_file_idx == lowfat_fs_file_count(fs_ptr));
        printf("CHECK: %u\n", check_idx++);
        auto check_res = check_lowfat_fs_files(fs_ptr, filenames, sizes, crcs, cur_empty_file_idx);
        assert(check_res);
        //
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
    }
    // test end
    std::vector<int32_t> descriptors = {};
    auto walker = [](int32_t fd, void* data) {
        auto fds = reinterpret_cast<std::vector<int32_t>*>(data);
        fds->emplace_back(fd);
    };
    lowfat_fs_walk_over_all_files(fs_ptr, &descriptors, walker);
    for (const auto fd : descriptors) {
        uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
        assert(freed_clusters != 0);
    }
    int64_t free_memory_calculated = lowfat_fs_total_size(fs_ptr) - lowfat_fs_system_used_size(fs_ptr);
    int64_t free_memory = lowfat_fs_free_mem_size(fs_ptr);
    assert(free_memory == free_memory_calculated);
    printf("File system randomized partial dump test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, lowfat_fs_total_size(fs_ptr)); 
    if (fs_ptr) {
        user_free(fs_ptr->_data);
        lowfat_fs_destroy_instance(fs_ptr);
    }
    
}

using THREADFUNC = int(*)(void const* data);

struct ThreadData_t {
    THREADFUNC func;
    void const* args;
    HANDLE start;
    uint64_t affinity_mask;
};

DWORD WINAPI win_thread_function(LPVOID lpParam) {
    auto const* thread_data = reinterpret_cast<const ThreadData_t*>(lpParam);
    THREADFUNC func = thread_data->func;
    void const* args = thread_data->args;
    HANDLE start = thread_data->start;
    uint64_t affinity_mask = thread_data->affinity_mask;
    if (affinity_mask > 0) {
        SetThreadAffinityMask(GetCurrentThread(), affinity_mask);
    }
    SetEvent(start);
    return func(args);
}

struct Thread {
    intptr_t handle;
};

std::wstring to_wstring(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

void set_thread_affinity(Thread thread, uint64_t mask) {
    SetThreadAffinityMask(reinterpret_cast<HANDLE>(thread.handle), mask);
}

Thread create_thread(const char* title_str, size_t stack_size, uint64_t affinity_mask, THREADFUNC func, void const* args) {
    HANDLE start = CreateEventEx(nullptr, nullptr, 0, EVENT_MODIFY_STATE | SYNCHRONIZE);
    const DWORD flags = stack_size ? STACK_SIZE_PARAM_IS_A_RESERVATION : 0;
    ThreadData_t thread_args{ func, args, start, affinity_mask };
    HANDLE thread = CreateThread(nullptr, stack_size, win_thread_function, &thread_args, flags, nullptr);
    WaitForSingleObject(start, INFINITE);
    CloseHandle(start);
    std::string title(title_str);
    std::wstring wtitle = to_wstring(title);
    SetThreadDescription(thread, wtitle.c_str());
    return Thread{ reinterpret_cast<intptr_t>(thread) };
}

void join_thread(Thread thread) {
    HANDLE thread_handle = reinterpret_cast<HANDLE>(thread.handle);
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
}

void test_lowfat_fs() {
    test_simple_rw();
    test_crc32();
    auto rw_test_func = [](void const* arg) {
        MAYBE_UNUSED(arg);
        test_randomized_rw(600.0f);
        return 0;
        };
    auto dump_test_func = [](void const* arg) {
        MAYBE_UNUSED(arg);
        test_randomized_dump(600.0f);
        return 0;
        };
    auto partial_dump_test_func = [](void const* arg) {
        MAYBE_UNUSED(arg);
        test_randomized_partial_dump(600.0f);
        return 0;
        };

    Thread rw_test_thread = create_thread("rw_test_thread", 0, 0, rw_test_func, nullptr);
    Thread dump_test_thread = create_thread("dump_test_thread", 0, 0, dump_test_func, nullptr);
    Thread partial_dump_test_thread = create_thread("partial_dump_test_thread", 0, 0, partial_dump_test_func, nullptr);
    join_thread(rw_test_thread);
    join_thread(dump_test_thread);
    join_thread(partial_dump_test_thread);
    LOWFAT_FS_ASSERT(allocated_table.empty());
    LOWFAT_FS_ASSERT(allocated_total == 0);
}

uint32_t fill_random_memory_block_and_calc_crc32(linkfs_memory_block_t* block) {
    RandomUint32Generator rand_gen;
    size_t size = block->size;
    uint32_t* block_data = reinterpret_cast<uint32_t*>(block->data);
    size_t idx = 0;
    while (size > 4) {
        block_data[idx++] = rand_gen();
        size -= 4;
    }
    for (idx = block->size - size; idx < block->size; idx++) {
        block->data[idx] = static_cast<uint8_t>(rand_gen() % 256);
    }
    return crc32_ccit_update(block->data, static_cast<uint32_t>(block->size), CRC32_CCIT_DEFAULT_VALUE);
}

enum class null_pointer_t {};
static const null_pointer_t null_pointer = {};

Result<write_info_t, null_pointer_t> write_to_linkfs_instance_random_file(linkfs* fs_ptr, size_t file_max_size, size_t file_block_max_size) {
    if (fs_ptr) {
        // always new file
        static size_t s_call_idx = 0;
        RandomUint32Generator rand_gen;
        write_info_t wrinfo = {};
        size_t file_size = static_cast<size_t>(max(16, rand_gen())) % file_max_size;
        size_t block_size = static_cast<size_t>(max(16, rand_gen())) % file_block_max_size;
        linkfs_memory_block_t* file_content = linkfs_create_memory_block(file_size);
        wrinfo.crc = fill_random_memory_block_and_calc_crc32(file_content);
        wrinfo.filesize = static_cast<uint32_t>(file_size);
        wrinfo.fname = "test_file_" + std::to_string(s_call_idx) + ".bin";
        s_call_idx++;
        linkfs_file_t* file_ptr = linkfs_open_new_file(fs_ptr, wrinfo.fname.c_str(), block_size);
        size_t bytes_written = linkfs_write_file(file_ptr, file_content);
        assert(bytes_written == file_content->size);
        linkfs_destroy_memory_block(file_content);
        return Result<write_info_t, null_pointer_t>(wrinfo);
    }
    return Result<write_info_t, null_pointer_t>(null_pointer);
}

void test_linkfs_simple_rw() {
    linkfs* fs_ptr = linkfs_create_instance();
    // revisit crc calculations
    const char test_abc[] = "ABC";
    uint32_t crc_test_0 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_abc),     3, CRC32_CCIT_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    uint32_t crc_test_1 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_abc),     1, CRC32_CCIT_DEFAULT_VALUE);
    uint32_t crc_test_2 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_abc) + 1, 1, crc_test_1 ^ 0xFFFFFFFF);
    uint32_t crc_test_3 = crc32_ccit_update(reinterpret_cast<const uint8_t*>(test_abc) + 2, 1, crc_test_2 ^ 0xFFFFFFFF);
    assert(crc_test_3 == crc_test_0);
    {
        const char* filename = "test0.bin";
        linkfs_memory_block_t* block = linkfs_create_memory_block(3);
        memcpy(block->data, test_abc, 3);
        linkfs_file_t* file_ptr = linkfs_open_new_file(fs_ptr, filename, 2);
        size_t written = linkfs_write_file(file_ptr, block);
        assert(written == block->size);
        assert(linkfs_total_size(fs_ptr) == 4ULL);
        assert(crc_test_3 == file_ptr->crc);
        linkfs_remove_file_str(fs_ptr, filename);
        assert(linkfs_total_size(fs_ptr) == 0ULL);
        linkfs_destroy_memory_block(block);
    }
    {
        const char* filename = "test1.bin";
        linkfs_memory_block_t* block = linkfs_create_memory_block(2049);
        uint32_t crc = fill_random_memory_block_and_calc_crc32(block);
        linkfs_file_t* file_ptr = linkfs_open_new_file(fs_ptr, filename, 1024);
        size_t written = linkfs_write_file(file_ptr, block);
        assert(written == block->size);
        assert(linkfs_total_size(fs_ptr) == 3072ULL);
        assert(crc == file_ptr->crc);
        linkfs_remove_file_str(fs_ptr, filename);
        assert(linkfs_total_size(fs_ptr) == 0ULL);
        linkfs_destroy_memory_block(block);
    }
    linkfs_destroy_instance(fs_ptr);
    assert(allocated_table.empty());
    assert(allocated_total == 0);
}

void test_linkfs_randomized_single_file_rw(const float duration) {
    const size_t min_file_block_size = 4; // 4 B
    const size_t min_file_size = min_file_block_size * 16; // 64 B
    const size_t max_file_block_size = 4096; // 4 KiB
    const size_t max_file_size = max_file_block_size * 16; // 64 KiB
    RandomUint32Generator rand_gen;
    linkfs* fs_ptr = linkfs_create_instance();
    size_t min_random_file_block_size = UINT64_MAX;
    size_t max_random_file_block_size = 0;
    size_t min_random_file_size = UINT64_MAX;
    size_t max_random_file_size = 0;
    size_t cycle_count = 0;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    while (elapsed.count() < duration) {
        size_t cur_file_block_size = static_cast<size_t>(rand_gen()) % (max_file_block_size - min_file_block_size) + min_file_block_size;
        size_t cur_file_size = static_cast<size_t>(rand_gen()) % (max_file_size - min_file_size) + min_file_size;
        linkfs_file_t* file_ptr = linkfs_open_new_file(fs_ptr, "test_0.bin", cur_file_block_size);
        linkfs_memory_block_t* block_ptr = linkfs_create_memory_block(cur_file_size);
        uint32_t crc = fill_random_memory_block_and_calc_crc32(block_ptr);
        size_t written = linkfs_write_file(file_ptr, block_ptr);
        assert(written == block_ptr->size);
        linkfs_destroy_memory_block(block_ptr);
        assert(crc == file_ptr->crc);
        linkfs_remove_file(fs_ptr, file_ptr);
        min_random_file_block_size = min(min_random_file_block_size, cur_file_block_size);
        max_random_file_block_size = max(max_random_file_block_size, cur_file_block_size);
        min_random_file_size = min(min_random_file_size, cur_file_size);
        max_random_file_size = max(max_random_file_size, cur_file_size);
        cycle_count++;
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        static auto prev_passed = elapsed.count();
        const auto cur_passed = elapsed.count();
        if (cur_passed - prev_passed > 1.0f) {
            printf("[ linkfs ] test_linkfs_randomized_single_file_rw: finished %.1f%% \n", cur_passed / duration * 100.0f);
            prev_passed = cur_passed;
        }
    }
    linkfs_destroy_instance(fs_ptr);
    assert(allocated_table.empty());
    assert(allocated_total == 0);
    printf("[ linkfs ] randomized single file rw test finished (%" PRIu64 " cycles): file block size varied from %" PRIu64 " to %" PRIu64 ", file size varied from %" PRIu64 " to %" PRIu64 "\n",
        cycle_count, min_random_file_block_size, max_random_file_block_size, min_random_file_size, max_random_file_size);
}

void test_linkfs() {
    test_linkfs_simple_rw();
    test_linkfs_randomized_single_file_rw(240.0f);
}

extern "C" {
    int main()
    {
        //test_lowfat_fs();
        test_linkfs();
        return 0;
    }
}
