project("lowfatfs")
    kind("StaticLib")
    targetname("lowfatfs")
    files({"../../source/lowfatfs/src/lowfatfs.c", 
 	   "../../source/lowfatfs/inc/lowfatfs.h",
 	   "../../source/lowfatfs/inc/lowfatfs_defines.h",	
 	   "../../source/lowfatfs/inc/lowfatfs_prelude.h",
	   "../../source/structures/inc/structures.h",
	   "../../source/structures/inc/structures_prelude.h"})
    includedirs({"../../source/lowfatfs/inc/", "../../source/structures/inc/", "../../source/crc/inc/"})
    location("../../build/lowfatfs")
    targetdir("../../build/lowfatfs/bin")
    objdir("../../build/lowfatfs/obj")
    exceptionhandling("On")
    defines { "_LIB", "LOWFAT_FS_VERBOSITY=LOWFAT_FS_VERBOSITY_DETAILED", "LOWFAT_FS_CUSTOM_ALLOCATOR", "LOWFAT_FS_ASSERT_ENABLED" }
    links {"crc"}
    --libdirs {"../../build/crc/lib"}