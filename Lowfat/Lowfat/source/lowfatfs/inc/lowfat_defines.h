#pragma once

#define LOWFAT_FS_OK                                0
#define LOWFAT_FS_NONE                             -1

#define LOWFAT_FS_FILE_LOCKED                       1
#define LOWFAT_FS_FILE_READ                         2
#define LOWFAT_FS_FILE_WRITE                        4

#define LOWFAT_FS_CLUSTER_TOUCHED                   1

#define LOWFAT_FS_FILE_LRW_INV_MASK                (0xFF ^ (LOWFAT_FS_FILE_LOCKED | LOWFAT_FS_FILE_READ | LOWFAT_FS_FILE_WRITE))

#define LOWFAT_FS_ERROR_DATA_TABLE_ENDED           -2
#define LOWFAT_FS_ERROR_SPACE_ENDED                -3
#define LOWFAT_FS_ERROR_SYSTEM_SECTION             -4

#define LOWFAT_FS_ERROR_FILE_NOT_FOUND             -5
#define LOWFAT_FS_ERROR_FILE_ALREADY_OPENED        -6
#define LOWFAT_FS_ERROR_FILE_NAME_NULL             -7
#define LOWFAT_FS_ERROR_FILE_NAME_TOO_LONG         -8
#define LOWFAT_FS_ERROR_FILE_WRONG_MODE            -9
#define LOWFAT_FS_ERROR_FILE_READ_SIZE_OVERFLOW    -10

#define LOWFAT_FS_VERBOSITY_MIN                     0
#define LOWFAT_FS_VERBOSITY_MINIMAL                 1
#define LOWFAT_FS_VERBOSITY_DETAILED                2
#define LOWFAT_FS_VERBOSITY_MAX	                 3

#ifdef LOWFAT_FS_ASSERT_ENABLED
#define LOWFAT_FS_ASSERT(expr) do { if (!(expr)) { fprintf(stderr, "%s (%d): Assertion failed.\n", __FILE__, __LINE__); fflush(stderr); __debugbreak();} } while(0)
#else 
#define LOWFAT_FS_ASSERT(expr) do {} while(0)
#endif
