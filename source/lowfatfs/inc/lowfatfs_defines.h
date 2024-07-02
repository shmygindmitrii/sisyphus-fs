#pragma once

#define LOWFATFS_OK                                0
#define LOWFATFS_NONE                             -1

#define LOWFATFS_FILE_LOCKED                       1
#define LOWFATFS_FILE_READ                         2
#define LOWFATFS_FILE_WRITE                        4

#define LOWFATFS_CLUSTER_TOUCHED                   1

#define LOWFATFS_FILE_LRW_INV_MASK                (0xFF ^ (LOWFATFS_FILE_LOCKED | LOWFATFS_FILE_READ | LOWFATFS_FILE_WRITE))

#define LOWFATFS_ERROR_DATA_TABLE_ENDED           -2
#define LOWFATFS_ERROR_SPACE_ENDED                -3
#define LOWFATFS_ERROR_SYSTEM_SECTION             -4

#define LOWFATFS_ERROR_FILE_NOT_FOUND             -5
#define LOWFATFS_ERROR_FILE_ALREADY_OPENED        -6
#define LOWFATFS_ERROR_FILE_NAME_NULL             -7
#define LOWFATFS_ERROR_FILE_NAME_TOO_LONG         -8
#define LOWFATFS_ERROR_FILE_WRONG_MODE            -9
#define LOWFATFS_ERROR_FILE_READ_SIZE_OVERFLOW    -10

#define LOWFATFS_VERBOSITY_MIN                     0
#define LOWFATFS_VERBOSITY_MINIMAL                 1
#define LOWFATFS_VERBOSITY_DETAILED                2
#define LOWFATFS_VERBOSITY_MAX	                 3

#ifdef LOWFATFS_ASSERT_ENABLED
#define LOWFATFS_ASSERT(expr) do { if (!(expr)) { fprintf(stderr, "%s (%d): Assertion failed.\n", __FILE__, __LINE__); fflush(stderr); __debugbreak();} } while(0)
#else 
#define LOWFATFS_ASSERT(expr) do {} while(0)
#endif
