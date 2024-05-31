#pragma once

#define LF_OK                                0
#define LF_NONE                             -1

#define LF_FILE_LOCKED                       1
#define LF_FILE_READ                         2
#define LF_FILE_WRITE                        4

#define LF_CLUSTER_TOUCHED                   1

#define LF_FILE_LRW_INV_MASK                (0xFF ^ (LF_FILE_LOCKED | LF_FILE_READ | LF_FILE_WRITE))

#define LF_ERROR_DATA_TABLE_ENDED           -2
#define LF_ERROR_SPACE_ENDED                -3
#define LF_ERROR_SYSTEM_SECTION             -4

#define LF_ERROR_FILE_NOT_FOUND             -5
#define LF_ERROR_FILE_ALREADY_OPENED        -6
#define LF_ERROR_FILE_NAME_NULL             -7
#define LF_ERROR_FILE_NAME_TOO_LONG         -8
#define LF_ERROR_FILE_WRONG_MODE            -9
#define LF_ERROR_FILE_READ_SIZE_OVERFLOW    -10

#define LF_VERBOSITY_MIN                     0
#define LF_VERBOSITY_MINIMAL                 1
#define LF_VERBOSITY_DETAILED                2
#define LF_VERBOSITY_MAX	                 3

#ifdef LOWFAT_ASSERT_ENABLED
#define LOWFAT_ASSERT(expr) do { if (!(expr)) { fprintf(stderr, "%s (%d): Assertion failed.\n", __FILE__, __LINE__); fflush(stderr); __debugbreak();} } while(0)
#else 
#define LOWFAT_ASSERT(expr) do {} while(0)
#endif
