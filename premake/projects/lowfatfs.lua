project("lowfatfs")
    kind("StaticLib")
    targetname("lowfatfs")
    files({
	"../../source/lowfatfs/src/lowfatfs.c", 
 	"../../source/lowfatfs/inc/lowfatfs.h",
 	"../../source/lowfatfs/inc/lowfatfs_defines.h",	
 	"../../source/lowfatfs/inc/lowfatfs_prelude.h",
	"../../source/structures/inc/structures.h",
        "../../source/structures/inc/structures_prelude.h"
    })
    includedirs({
        "../../source/lowfatfs/inc/", 
        "../../source/structures/inc/", 
        "../../source/crc/inc/"
    })
    location("../../build/lowfatfs")
    targetdir("../../build/lowfatfs/bin")
    objdir("../../build/lowfatfs/obj")
    exceptionhandling("On")
    defines { 
        "_LIB", 
        "LOWFATFS_VERBOSITY=LOWFATFS_VERBOSITY_DETAILED", 
        "LOWFATFS_CUSTOM_ALLOCATOR", 
        "LOWFATFS_ASSERT_ENABLED" 
    }
    links {
        "crc"
    }
    warnings "Extra"
    flags { 
        "FatalCompileWarnings" 
    }