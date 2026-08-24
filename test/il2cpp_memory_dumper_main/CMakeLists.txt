cmake_minimum_required(VERSION 3.10)
project(il2cpp_memory_dumper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Source files
set(SOURCES
    main.cpp
    utils.cpp
    memory_map.cpp
    memory_scanner.cpp
    elf_fixer.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
