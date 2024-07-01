print "Windows"

function create_solution_win(solution_name)
    print("Create solution \"" .. solution_name .. "\" for platform windows")
    workspace(solution_name)
        configurations { "Debug", "Release" }
        architecture "x64"
        defines { "WIN32", "_CONSOLE" }
        language "C++"
        location(SOLUTION_VARS.project_output_directory)

    filter "configurations:Debug"
        defines { "_DEBUG" }
        optimize "Off"
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"

    filter {}
end


