cmake_minimum_required(VERSION 3.4.1)

project(agent)

add_library( # Specifies the name of the library.
    agent

    # Sets the library as a shared library.
    SHARED

    # Provides a relative path to your source file(s).
    main.cpp)

find_library( # Defines the name of the path variable that stores the

    # location of the NDK library.
    log-lib

    # Specifies the name of the NDK library that
    # CMake needs to locate.
    log)

target_link_libraries( # Specifies the target library.
    agent

    # Links the log library to the target library.
    ${log-lib})
