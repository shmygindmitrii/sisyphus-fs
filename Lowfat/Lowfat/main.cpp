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

#include "unordered_map"

static std::unordered_map<intptr_t, size_t> allocated_table = {};
static size_t allocated_total = 0;

void* user_malloc(size_t size) {
    void* ptr = malloc(size);
    allocated_table[(intptr_t)ptr] = size;
    allocated_total += size;
    return ptr;
}

void user_free(void* ptr) {
    assert(allocated_table.find((intptr_t)ptr) != allocated_table.end());
    free(ptr);
    allocated_total -= allocated_table[(intptr_t)ptr];
    allocated_table.erase((intptr_t)ptr);
}

uint32_t fill_random_byte_buffer_and_calc_crc32(std::vector<uint8_t>& mem) {
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

void test_fs_readback(lowfat_fs* fs_ptr, double test_period) {
    uint32_t file_idx = 0;
    std::vector<lowfat_filename_t> filenames;
    std::vector<uint32_t> crcs;
    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cur_empty_file_idx = 0;
    uint32_t cycle_idx = 0;
    uint32_t writes_count = 0;
    MemAmount_t rewritten_memory{};

    while (elapsed.count() < test_period) {
        size_t available = lowfat_fs_free_available_mem_size(fs_ptr); // not tight, free clusters * cluster_size
        if (available) {
            // have a place to write
            size_t random_filesize = (rand() % lowfat_fs_total_size(fs_ptr)) % (available - lowfat_fs_cluster_size(fs_ptr) / 4) + lowfat_fs_cluster_size(fs_ptr) / 4;
            if (cur_empty_file_idx == (uint32_t)crcs.size()) {
                // push_back new one
                crcs.push_back(0);
                CREATE_LOWFAT_FILENAME(fname, lowfat_fs_filename_length(fs_ptr), user_malloc);
                filenames.push_back(fname);
            }
            std::vector<uint8_t> mem(random_filesize);
            crcs[cur_empty_file_idx] = fill_random_byte_buffer_and_calc_crc32(mem);
            lowfat_filename_t filename = filenames[cur_empty_file_idx];
            snprintf(filename.name, filename.size, "test_file_%u_%u.bin", cycle_idx, cur_empty_file_idx);
#if _DEBUG
            printf("try to save \"%s\" of size %u\n", filename.name, (uint32_t)random_filesize);
#endif
            int32_t fd = lowfat_fs_open_file(fs_ptr, filename.name, 'w');
            uint32_t written = lowfat_fs_write_file(fs_ptr, mem.data(), (uint32_t)mem.size(), 1, fd);
            lowfat_fs_close_file(fs_ptr, fd);
            assert(written == 1);
            lowfat_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
            assert(finfo.name != nullptr);
            assert(crcs[cur_empty_file_idx] == finfo.props->crc32);
            rewritten_memory += mem.size();
            cur_empty_file_idx++;
            writes_count++;
        }
        else {
            // need to free place
            uint32_t files_written = lowfat_fs_file_count(fs_ptr);
            uint32_t files_to_remove = (rand() % (files_written - 1)) + 1;
#if _DEBUG
            printf("Space finished, free procedure for %u files of %u \n", files_to_remove, files_written);
#endif
            for (uint32_t i = 0; i < files_to_remove; i++) {
                // need a vector of filenames
                uint32_t cur_file_idx = rand() % files_written;
                int fd = lowfat_fs_open_file(fs_ptr, filenames[cur_file_idx].name, 'r');
                assert(fd >= LF_OK);
                lowfat_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
                assert(finfo.name != nullptr);
                std::vector<uint8_t> mem(finfo.props->size);
                int32_t read = lowfat_fs_read_file(fs_ptr, mem.data(), 1, (uint32_t)mem.size(), fd);
                lowfat_fs_close_file(fs_ptr, fd);
                uint32_t test_crc32 = crc32_ccit_update(mem.data(), (uint32_t)mem.size(), CRC32_CCIT_DEFAULT_VALUE);
                assert(test_crc32 == crcs[cur_file_idx] && test_crc32 == finfo.props->crc32);
                uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
                assert(freed_clusters == ((uint32_t)mem.size() / lowfat_fs_cluster_size(fs_ptr) + ((uint32_t)mem.size() % lowfat_fs_cluster_size(fs_ptr) > 0)));
                //
#if _DEBUG
                printf("Removed '%s'\n", filenames[cur_file_idx].name);
#endif
                if (cur_file_idx != files_written - 1) {
                    assert(strcmp(filenames[cur_file_idx].name, filenames[cur_empty_file_idx - 1].name) != 0);
                    lowfat_filename_t tmp = filenames[cur_file_idx];
                    filenames[cur_file_idx] = filenames[files_written - 1];
                    filenames[files_written - 1] = tmp;
                    crcs[cur_file_idx] = crcs[files_written - 1];
                }
                filenames[files_written - 1].name[0] = '\0'; // do not destroy, but nullify name
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
        int fd = lowfat_fs_open_file(fs_ptr, filenames[i].name, 'r');
        assert(fd >= LF_OK);
        lowfat_fileinfo_t finfo = lowfat_fs_file_stat(fs_ptr, fd);
        assert(finfo.name != nullptr);
        std::vector<uint8_t> mem(finfo.props->size);
        int32_t read = lowfat_fs_read_file(fs_ptr, mem.data(), 1, (uint32_t)mem.size(), fd);
        lowfat_fs_close_file(fs_ptr, fd);
        uint32_t test_crc32 = crc32_ccit_update(mem.data(), (uint32_t)mem.size(), CRC32_CCIT_DEFAULT_VALUE);
        assert(test_crc32 == crcs[i] && test_crc32 == finfo.props->crc32);
        uint32_t freed_clusters = lowfat_fs_remove_file(fs_ptr, fd);
        assert(freed_clusters == (mem.size() / lowfat_fs_cluster_size(fs_ptr) + (mem.size() % lowfat_fs_cluster_size(fs_ptr) > 0)));
    }
    uint32_t mem_busy = lowfat_fs_cluster_count(fs_ptr) * lowfat_fs_cluster_size(fs_ptr) - (uint32_t)lowfat_fs_free_mem_size(fs_ptr);
    assert(mem_busy == lowfat_fs_system_used_size(fs_ptr));
    // do not forget to remove everything
    for (uint32_t i = 0; i < filenames.size(); i++) {
        DESTROY_LOWFAT_FILENAME_CONTENT(filenames[i], user_free);
    }
    printf("File system randomized RW test finished: %zu MB, %zu KB, %zu bytes were rewritten for fs of size %u \n", rewritten_memory.megabytes, rewritten_memory.kilobytes, rewritten_memory.bytes, lowfat_fs_total_size(fs_ptr));
}

void test_crc32() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), user_malloc);
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);
    //
    const char test_abc[] = "ABC";
    const char test_d[] = "D";
    uint32_t crc_test_3 = crc32_ccit_update((uint8_t*)test_abc, 3, CRC32_CCIT_DEFAULT_VALUE); // start from filled to do not shift initial crc zeros
    // https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art008
    assert(crc_test_3 == 0xa3830348);
    printf("ABC remainder lookuped: %#010x\n", crc_test_3);
    crc_test_3 = crc32_ccit_update((uint8_t*)test_d, 1, crc_test_3);
    printf("ABCD remainder lookuped: %#010x\n", crc_test_3);
    {
        int32_t abc_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'w');
        lowfat_fs_write_file(fs_ptr, (uint8_t*)test_abc, 3, 1, abc_fd);
        lowfat_fs_write_file(fs_ptr, (uint8_t*)test_d, 1, 1, abc_fd);
        lowfat_fs_close_file(fs_ptr, abc_fd);
        const lowfat_fileinfo_t fst = lowfat_fs_file_stat(fs_ptr, abc_fd);
        printf("File remainder lookuped: %#010x\n", fst.props->crc32);
    }
    lowfat_fs_destroy_instance(fs_ptr, user_free);
    LOWFAT_ASSERT(allocated_table.empty());
    LOWFAT_ASSERT(allocated_total == 0);
}

void test_simple_rw() {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), user_malloc);
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);

    const int max_user_file_count = lowfat_fs_cluster_count(fs_ptr) - lowfat_fs_system_used_clusters(fs_ptr);
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = lowfat_fs_open_file(fs_ptr, filename, 'w');
        assert(test >= 0);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t remove_res = lowfat_fs_remove_file_str(fs_ptr, filename);
    }
    for (int i = 0; i < max_user_file_count; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i);
        int32_t test = lowfat_fs_open_file(fs_ptr, filename, 'w');
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test);
    }
    for (int i = 5; i < max_user_file_count + 5; i++) {
        char filename[fs_filename_max_length] = { 0 };
        snprintf(filename, fs_filename_max_length, "test%d.txt", i % max_user_file_count);
        int32_t remove_res = lowfat_fs_remove_file_str(fs_ptr, filename);
    }
    {
        int32_t test_fd = lowfat_fs_open_file(fs_ptr, "three.txt", 'w');
        uint8_t test_buf[fs_cluster_size * 3] = { 0 };
        memset(test_buf, 1, fs_cluster_size * 3);
        lowfat_fs_write_file(fs_ptr, test_buf, 1, fs_cluster_size * 3, test_fd);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test_fd);
    }
    {
        int32_t test_fd = lowfat_fs_open_file(fs_ptr, "three_and_half.txt", 'w');
        uint8_t test_buf[fs_cluster_size / 2] = { 0 };
        memset(test_buf, 2, fs_cluster_size / 2);
        lowfat_fs_write_file(fs_ptr, test_buf, 1, fs_cluster_size / 2, test_fd);
        int32_t close_res = lowfat_fs_close_file(fs_ptr, test_fd);
    }
    {
        char text[1536] = { '\0' };
        int32_t switcher = 1536 / ('z' - 'a' + 1);
        for (int i = 0; i < 1536; i++) {
            text[i] = 'a' + i / switcher;
        }
        int32_t text_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'w');
        lowfat_fs_write_file(fs_ptr, (uint8_t*)(text), 1, sizeof(text), text_fd);
        lowfat_fs_close_file(fs_ptr, text_fd);
    }
    {
        int32_t text_fd = lowfat_fs_open_file(fs_ptr, "saved_text.txt", 'r');
        lowfat_fileinfo_t file_info = lowfat_fs_file_stat(fs_ptr, text_fd);
        char* text = new char[file_info.props->size];
        lowfat_fs_read_file(fs_ptr, (uint8_t*)text, 1, file_info.props->size, text_fd);
        lowfat_fs_close_file(fs_ptr, text_fd);
        delete[] text;
    }
    lowfat_fs_destroy_instance(fs_ptr, user_free);
    LOWFAT_ASSERT(allocated_table.empty());
    LOWFAT_ASSERT(allocated_total == 0);
}

void test_randomized_rw(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), user_malloc);
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);
    // test begin
    test_fs_readback(fs_ptr, duration);
    // test end
    lowfat_fs_destroy_instance(fs_ptr, user_free);
    LOWFAT_ASSERT(allocated_table.empty());
    LOWFAT_ASSERT(allocated_total == 0);
}

void test_randomized_dump(const float duration) {
    const uint32_t fs_cluster_size = 4 * 1024;
    const uint32_t fs_cluster_count = 1024;
    const uint32_t fs_filename_max_length = 32;
    std::vector<uint8_t> fs_mem(fs_cluster_count * fs_cluster_size, 0);
    lowfat_fs* fs_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, fs_mem.data(), user_malloc);
    lowfat_fs_set_instance_addresses(fs_ptr);
    lowfat_fs_reset_instance(fs_ptr);

    const auto start{ std::chrono::steady_clock::now() };
    auto end{ std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed = end - start;
    uint32_t cycle_idx = 0;
    while (elapsed.count() < duration) {
        uint32_t file_idx = 0;
        std::vector<uint32_t> crcs;
        std::vector <std::string> filenames;
        size_t available = lowfat_fs_free_available_mem_size(fs_ptr);
        while (available) {
            size_t random_filesize = (rand() % lowfat_fs_total_size(fs_ptr)) % (available - lowfat_fs_cluster_size(fs_ptr) / 4) + lowfat_fs_cluster_size(fs_ptr) / 4;
            std::vector<uint8_t> mem(random_filesize, 0);
            uint32_t crc = fill_random_byte_buffer_and_calc_crc32(mem);
            char filename[fs_filename_max_length] = {};
            snprintf(filename, fs_filename_max_length, "test_file_%d.bin", file_idx);
            int fd = lowfat_fs_open_file(fs_ptr, filename, 'w');
            lowfat_fs_write_file(fs_ptr, mem.data(), 1, (uint32_t)mem.size(), fd);
            lowfat_fs_close_file(fs_ptr, fd);
            available = lowfat_fs_free_available_mem_size(fs_ptr);
            //
            file_idx++;
            crcs.push_back(crc);
            filenames.push_back(filename);
        }
        // finished fullfilling of fs
        std::vector<uint8_t> dumped(lowfat_fs_total_size(fs_ptr) + sizeof(uint64_t) * 2, 0);
        memcpy(&dumped[0], &LOWFAT_FS_DUMP_BEGIN_MARKER, sizeof(uint64_t));
        memcpy(&dumped[sizeof(uint64_t) + lowfat_fs_total_size(fs_ptr)], &LOWFAT_FS_DUMP_END_MARKER, sizeof(uint64_t));
        memcpy(&dumped[sizeof(uint64_t)], fs_mem.data(), lowfat_fs_total_size(fs_ptr));
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
        uint64_t end_val = *((uint64_t*)(redumped.data() + lowfat_fs_total_size(fs_ptr) + sizeof(uint64_t)));
        assert(start_val == LOWFAT_FS_DUMP_BEGIN_MARKER && end_val == LOWFAT_FS_DUMP_END_MARKER);

        lowfat_fs* fs_ref_ptr = lowfat_fs_create_instance(fs_cluster_size, fs_cluster_count, fs_filename_max_length, redumped.data() + sizeof(uint64_t), user_malloc);
        lowfat_fs_set_instance_addresses(fs_ref_ptr);
        // no reset here, because want to reuse
        assert(lowfat_fs_file_count(fs_ptr) == lowfat_fs_file_count(fs_ref_ptr));
        assert(lowfat_fs_file_count(fs_ref_ptr) == filenames.size());
        const uint32_t file_count = lowfat_fs_file_count(fs_ref_ptr);
        for (uint32_t i = 0; i < file_count; i++) {
            lowfat_fileinfo_t fi = lowfat_fs_file_stat_str(fs_ref_ptr, filenames[i].c_str());
            int32_t fd = lowfat_fs_open_file(fs_ref_ptr, filenames[i].c_str(), 'r');
            std::vector<uint8_t> data(fi.props->size);
            lowfat_fs_read_file(fs_ref_ptr, data.data(), 1, fi.props->size, fd);
            uint32_t recrc = crc32_ccit_update(data.data(), fi.props->size, CRC32_CCIT_DEFAULT_VALUE);
            assert(recrc == crcs[i] && recrc == fi.props->crc32);
            lowfat_fs_close_file(fs_ref_ptr, fd);
            lowfat_fs_remove_file(fs_ref_ptr, fd);
        }
        uint32_t sys_used_mem = lowfat_fs_total_size(fs_ref_ptr) - lowfat_fs_free_available_mem_size(fs_ref_ptr);
        uint32_t sys_used_mem_ref = lowfat_fs_system_used_clusters(fs_ref_ptr) * lowfat_fs_cluster_size(fs_ref_ptr);
        assert(sys_used_mem == sys_used_mem_ref);
        for (uint32_t i = 0; i < file_count; i++) {
            lowfat_fs_remove_file_str(fs_ptr, filenames[i].c_str());
        }
        uint32_t sys_used_mem0 = (uint32_t)lowfat_fs_total_size(fs_ref_ptr) - lowfat_fs_free_available_mem_size(fs_ref_ptr);
        uint32_t sys_used_mem_ref0 = lowfat_fs_system_used_clusters(fs_ref_ptr) * lowfat_fs_cluster_size(fs_ref_ptr);
        assert(sys_used_mem0 == sys_used_mem_ref0);
        //
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        cycle_idx++;
        lowfat_fs_destroy_instance(fs_ref_ptr, user_free);
    }
    printf("File system randomized dump test finished: %u cycles of fullfilling and working over dumped fs\n", cycle_idx);
    lowfat_fs_destroy_instance(fs_ptr, user_free);
    LOWFAT_ASSERT(allocated_table.empty());
    LOWFAT_ASSERT(allocated_total == 0);
}

extern "C" {
    int main()
    {
        srand((uint32_t)time(nullptr));
        test_simple_rw();
        test_crc32();
        test_randomized_rw(240.0f);
        test_randomized_dump(240.0f);
        return 0;
    }
}
