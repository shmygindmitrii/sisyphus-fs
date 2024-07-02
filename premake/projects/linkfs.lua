project("linkfs")
    kind("StaticLib")
    targetname("linkfs")
    files({
        "../../source/linkfs/src/linkfs.c", 
 	"../../source/linkfs/inc/linkfs.h",
 	"../../source/linkfs/inc/linkfs_defines.h",	
 	"../../source/linkfs/inc/linkfs_prelude.h"
    })
    includedirs({
        "../../source/linkfs/inc/", 
        "../../source/crc/inc/"
    })
    location("../../build/linkfs")
    targetdir("../../build/linkfs/bin")
    objdir("../../build/linkfs/obj")
    exceptionhandling("On")
    defines { 
        "_LIB", 
        "LINKFS_CUSTOM_DEBUGBREAK", 
        "LINKFS_CUSTOM_ALLOCATOR", 
        "LINKFS_ASSERT_ENABLED" 
    }
    links {
        "crc"
    }
    warnings "Extra"
    flags { 
        "FatalCompileWarnings" 
    }
