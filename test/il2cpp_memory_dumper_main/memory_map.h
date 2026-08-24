#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Represents a single memory mapping from /proc/pid/maps
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    std::string perms;      // rwxp
    std::string pathname;   // file path or [heap], [stack], etc.
    bool is_readable;
    bool is_writable;
    bool is_executable;
    bool is_private;

    uint64_t size() const { return end - start; }
};

class ProcessMemory {
public:
    explicit ProcessMemory(pid_t pid);

    // Parse /proc/pid/maps
    bool parse_maps();

    // Find regions matching a library name (exact or partial)
    std::vector<MemoryRegion> find_library_regions(const std::string& lib_name) const;

    // Find regions by partial name match (for anon mappings, deleted files, etc.)
    std::vector<MemoryRegion> find_regions_by_partial_name(const std::string& partial) const;

    // Find region matching a file name (for metadata)
    std::vector<MemoryRegion> find_file_regions(const std::string& filename) const;

    // Dump specific region to buffer
    bool dump_region(const MemoryRegion& region, std::vector<uint8_t>& out) const;

    // Dump all regions of a library and reconstruct ELF
    bool dump_library(const std::string& lib_name, const std::string& output_path) const;

    // Dump metadata file from memory
    bool dump_metadata(const std::string& output_path) const;

    // Get all parsed regions
    const std::vector<MemoryRegion>& regions() const { return regions_; }

    pid_t pid() const { return pid_; }

private:
    pid_t pid_;
    std::vector<MemoryRegion> regions_;

    bool read_memory(uint64_t addr, size_t size, std::vector<uint8_t>& out) const;
};
