project("tests")
    kind("ConsoleApp")
    language "C++"
    cppdialect "C++17"
    targetname("tests")
    files({
        "../../source/tests/src/main.cpp"
    })
    includedirs({
        "../../source/lowfatfs/inc/", 
        "../../source/linkfs/inc/", 
        "../../source/structures/inc/", 
        "../../source/crc/inc/"
    })
    location("../../build/tests")
    targetdir("../../build/tests/bin")
    objdir("../../build/tests/obj")
    exceptionhandling("On")
    links {
        "crc", 
        "linkfs", 
        "lowfatfs"
    }
    warnings "Extra"
    flags { 
        "FatalCompileWarnings" 
    }


