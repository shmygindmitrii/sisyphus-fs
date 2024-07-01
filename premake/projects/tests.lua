project("tests")
    kind("ConsoleApp")
    language "C++"
    cppdialect "C++17"
    targetname("tests")
    files({"../../source/tests/src/main.cpp"})
    includedirs({"../../source/lowfatfs/inc/", "../../source/linkfs/inc/", "../../source/structures/inc/", "../../source/crc/inc/"})
    location("../../build/tests")
    targetdir("../../build/tests/bin")
    objdir("../../build/tests/obj")
    exceptionhandling("On")
    --defines { "LINKFS_CUSTOM_ALLOCATOR", "LINKFS_ASSERT_ENABLED", "LOWFAT_FS_VERBOSITY=LOWFAT_FS_VERBOSITY_DETAILED", "LOWFAT_FS_CUSTOM_ALLOCATOR", "LOWFAT_FS_ASSERT_ENABLED" }
    links {"crc", "linkfs", "lowfatfs"}
    --libdirs {"../../build/crc/lib", "../../build/linkfs/lib", "../../build/lowfatfs/lib"}
