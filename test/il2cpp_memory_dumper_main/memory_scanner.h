#pragma once

#include "memory_map.h"
#include <vector>
#include <cstdint>

// Advanced memory scanner for finding hidden/encrypted IL2CPP data
class MemoryScanner {
public:
    explicit MemoryScanner(const ProcessMemory& mem);

    // Find all ELF headers in memory (for packed/encrypted libs)
    struct ElfMatch {
        uint64_t addr;
        bool is64bit;
        uint64_t size_hint;
    };
    std::vector<ElfMatch> scan_for_elf_headers() const;

    // Find metadata by sanity bytes (checks only region starts - fast)
    struct MetadataMatch {
        uint64_t addr;
        uint32_t version;
        uint64_t size_hint;
    };
    std::vector<MetadataMatch> scan_for_metadata() const;

    // DEEP SCAN: scan entire memory of each region for metadata signature
    std::vector<MetadataMatch> deep_scan_for_metadata() const;

    // Find IL2CPP API functions inside libunity.so by signature
    struct Il2CppApiMatch {
        uint64_t addr;
        std::string name;
        std::vector<uint8_t> signature;
    };
    std::vector<Il2CppApiMatch> find_il2cpp_api(uint64_t module_base, size_t module_size) const;

    // Find large anonymous executable regions (likely packed libs)
    std::vector<MemoryRegion> find_large_anon_executable() const;

    // Dump ELF by scanning for header
    bool dump_elf_by_scan(const std::string& output_path, uint64_t& out_base) const;

    // Dump metadata by scanning for sanity bytes
    bool dump_metadata_by_scan(const std::string& output_path) const;

    // Deep scan dump
    bool deep_dump_metadata(const std::string& output_path) const;

private:
    const ProcessMemory& mem_;

    bool read_safe(uint64_t addr, size_t size, std::vector<uint8_t>& out) const;
    std::vector<MetadataMatch> scan_region_for_metadata(const MemoryRegion& region) const;
    size_t estimate_metadata_size(const uint8_t* header) const;
};
