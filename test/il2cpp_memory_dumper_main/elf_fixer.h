#pragma once

#include <cstdint>
#include <vector>
#include <string>

// Rebuilds ELF section headers from program headers
// This is needed because dumped ELF from memory loses section headers
class ElfFixer {
public:
    // Fix a dumped ELF file
    // base_addr: the original load address in memory
    static bool fix_elf(const std::string& input_path, const std::string& output_path, uint64_t base_addr);

    // Fix in-memory buffer
    static bool fix_elf_buffer(std::vector<uint8_t>& data, uint64_t base_addr);

private:
    static bool fix_elf64(std::vector<uint8_t>& data, uint64_t base_addr);
    static bool fix_elf32(std::vector<uint8_t>& data, uint64_t base_addr);

    // Create minimal section headers
    static void create_section_headers_64(std::vector<uint8_t>& data, 
                                          const std::vector<uint8_t>& original,
                                          uint64_t base_addr);
};
