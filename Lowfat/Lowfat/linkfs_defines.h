#pragma once

#define LINKFS_OK                                0
#define LINKFS_NONE                             -1

#define LINKFS_FILE_LOCKED                       1
#define LINKFS_FILE_READ                         2
#define LINKFS_FILE_WRITE                        4

#define LINKFS_CLUSTER_TOUCHED                   1

#define LINKFS_FILE_LRW_INV_MASK                (0xFF ^ (LINKFS_FILE_LOCKED | LINKFS_FILE_READ | LINKFS_FILE_WRITE))

#define LINKFS_ERROR_DATA_TABLE_ENDED           -2
#define LINKFS_ERROR_SPACE_ENDED                -3
#define LINKFS_ERROR_SYSTEM_SECTION             -4

#define LINKFS_ERROR_FILE_NOT_FOUND             -5
#define LINKFS_ERROR_FILE_ALREADY_OPENED        -6
#define LINKFS_ERROR_FILE_NAME_NULL             -7
#define LINKFS_ERROR_FILE_NAME_TOO_LONG         -8
#define LINKFS_ERROR_FILE_WRONG_MODE            -9
#define LINKFS_ERROR_FILE_READ_SIZE_OVERFLOW    -10

#define LINKFS_VERBOSITY_MIN                     0
#define LINKFS_VERBOSITY_MINIMAL                 1
#define LINKFS_VERBOSITY_DETAILED                2
#define LINKFS_VERBOSITY_MAX	                 3

#ifdef LINKFS_ASSERT_ENABLED
#define LINKFS_ASSERT(expr) do { if (!(expr)) { fprintf(stderr, "%s (%d): Assertion failed.\n", __FILE__, __LINE__); fflush(stderr); __debugbreak();} } while(0)
#else 
#define LINKFS_ASSERT(expr) do {} while(0)
#endif
