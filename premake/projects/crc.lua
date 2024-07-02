project("crc")
    kind("StaticLib")
    targetname("crc")
    files({
        "../../source/crc/src/crc32_ccit.c", 
	"../../source/crc/inc/crc32_ccit.h"
    })
    includedirs({
        "../../source/crc/inc/"
    })
    location("../../build/crc")
    targetdir("../../build/crc/lib")
    objdir("../../build/crc/obj")
    exceptionhandling("On")
    defines { 
        "_LIB" 
    }
    warnings "Extra"
    flags { 
        "FatalCompileWarnings" 
    }