workspace("sisyphys-fs")
    configurations { "Debug", "Release" }
    architecture "x64"
    defines { "WIN32", "_CONSOLE" }
    language "C++"
    location("../build/")

filter "configurations:Debug"
    defines { "_DEBUG" }
    optimize "Off"
    symbols "On"

filter "configurations:Release"
    defines { "NDEBUG" }
    optimize "Full"

include("projects/crc")
include("projects/linkfs")
include("projects/lowfatfs")
include("projects/tests")

