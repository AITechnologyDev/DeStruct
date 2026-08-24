#!/bin/bash
set -e

echo "Building IL2CPP Memory Dumper..."

# Check for cmake
if command -v cmake &> /dev/null; then
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    echo ""
    echo "Build complete: ./build/il2cpp_memory_dumper"
else
    echo "cmake not found, trying direct g++ compilation..."
    g++ -std=c++17 -O3 -o il2cpp_memory_dumper \
        main.cpp utils.cpp memory_map.cpp elf_fixer.cpp
    echo "Build complete: ./il2cpp_memory_dumper"
fi
