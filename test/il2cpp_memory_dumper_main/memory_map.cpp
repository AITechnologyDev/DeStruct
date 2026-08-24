#include "memory_map.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <algorithm>
#include <cerrno>
#include <cstring>

ProcessMemory::ProcessMemory(pid_t pid) : pid_(pid) {}

static bool g_debug_maps = false;

static bool parse_maps_line(const std::string& line, MemoryRegion& region) {
    if (g_debug_maps) {
        LOGD("Parsing line: [%s]", line.c_str());
    }

    size_t pos = 0;
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) pos++;
    if (pos >= line.size()) return false;

    size_t dash_pos = line.find('-', pos);
    if (dash_pos == std::string::npos) {
        if (g_debug_maps) LOGD("  No dash found");
        return false;
    }

    std::string start_str = line.substr(pos, dash_pos - pos);
    pos = dash_pos + 1;

    size_t space_after_end = line.find(' ', pos);
    if (space_after_end == std::string::npos) {
        if (g_debug_maps) LOGD("  No space after end addr");
        return false;
    }

    std::string end_str = line.substr(pos, space_after_end - pos);
    pos = space_after_end + 1;

    while (pos < line.size() && line[pos] == ' ') pos++;
    if (pos + 4 > line.size()) {
        if (g_debug_maps) LOGD("  Not enough chars for perms");
        return false;
    }

    region.perms = line.substr(pos, 4);
    pos += 4;

    while (pos < line.size() && line[pos] == ' ') pos++;
    if (pos >= line.size()) {
        if (g_debug_maps) LOGD("  No offset");
        return false;
    }

    size_t offset_end = line.find(' ', pos);
    if (offset_end == std::string::npos) {
        if (g_debug_maps) LOGD("  No space after offset");
        return false;
    }
    std::string offset_str = line.substr(pos, offset_end - pos);
    pos = offset_end + 1;

    while (pos < line.size() && line[pos] == ' ') pos++;
    if (pos >= line.size()) {
        if (g_debug_maps) LOGD("  No dev");
        return false;
    }

    size_t dev_end = line.find(' ', pos);
    if (dev_end == std::string::npos) {
        if (g_debug_maps) LOGD("  No space after dev");
        return false;
    }
    std::string dev_str = line.substr(pos, dev_end - pos);
    pos = dev_end + 1;

    while (pos < line.size() && line[pos] == ' ') pos++;
    if (pos >= line.size()) {
        if (g_debug_maps) LOGD("  No inode");
        return false;
    }

    size_t inode_end = line.find(' ', pos);
    std::string inode_str;
    if (inode_end == std::string::npos) {
        inode_str = line.substr(pos);
        pos = line.size();
    } else {
        inode_str = line.substr(pos, inode_end - pos);
        pos = inode_end + 1;
    }

    while (pos < line.size() && line[pos] == ' ') pos++;
    if (pos < line.size()) {
        region.pathname = line.substr(pos);
    } else {
        region.pathname = "";
    }

    region.start = utils::hex_to_u64(start_str);
    region.end = utils::hex_to_u64(end_str);
    region.offset = utils::hex_to_u64(offset_str);

    region.is_readable = region.perms.length() > 0 && region.perms[0] == 'r';
    region.is_writable = region.perms.length() > 1 && region.perms[1] == 'w';
    region.is_executable = region.perms.length() > 2 && region.perms[2] == 'x';
    region.is_private = region.perms.length() > 3 && region.perms[3] == 'p';

    if (region.start == 0 && start_str != "00000000" && start_str != "0") {
        if (g_debug_maps) LOGD("  Invalid start address parse");
        return false;
    }
    if (region.end == 0 && end_str != "00000000" && end_str != "0") {
        if (g_debug_maps) LOGD("  Invalid end address parse");
        return false;
    }
    if (region.start >= region.end) {
        if (g_debug_maps) LOGD("  start >= end: 0x%llx >= 0x%llx",
             (unsigned long long)region.start, (unsigned long long)region.end);
        return false;
    }

    return true;
}

bool ProcessMemory::parse_maps() {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        LOGE("Failed to open %s (need root? error: %s)", maps_path.c_str(), strerror(errno));
        return false;
    }

    regions_.clear();
    std::string line;
    int line_num = 0;
    int skipped = 0;

    g_debug_maps = true;
    int debug_lines = 3;

    while (std::getline(maps_file, line)) {
        line_num++;

        if (debug_lines > 0) {
            debug_lines--;
        } else {
            g_debug_maps = false;
        }

        MemoryRegion region{};

        if (!parse_maps_line(line, region)) {
            skipped++;
            continue;
        }

        regions_.push_back(region);
    }

    if (skipped > 0) {
        LOGW("Skipped %d malformed lines out of %d total", skipped, line_num);
    }

    LOGI("Parsed %zu valid memory regions from %d lines", regions_.size(), line_num);

    if (regions_.empty() && line_num > 0) {
        LOGE("All lines were malformed!");
    }

    return true;
}

std::vector<MemoryRegion> ProcessMemory::find_library_regions(const std::string& lib_name) const {
    std::vector<MemoryRegion> result;

    for (const auto& region : regions_) {
        if (region.pathname.find(lib_name) != std::string::npos) {
            result.push_back(region);
        }
    }

    return result;
}

std::vector<MemoryRegion> ProcessMemory::find_regions_by_partial_name(const std::string& partial) const {
    std::vector<MemoryRegion> result;

    for (const auto& region : regions_) {
        if (region.pathname.find(partial) != std::string::npos) {
            result.push_back(region);
        }
    }

    return result;
}

std::vector<MemoryRegion> ProcessMemory::find_file_regions(const std::string& filename) const {
    std::vector<MemoryRegion> result;

    for (const auto& region : regions_) {
        if (region.pathname.find(filename) != std::string::npos) {
            result.push_back(region);
        }
    }

    return result;
}

bool ProcessMemory::read_memory(uint64_t addr, size_t size, std::vector<uint8_t>& out) const {
    std::string mem_path = "/proc/" + std::to_string(pid_) + "/mem";
    int fd = open(mem_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("Failed to open %s: %s", mem_path.c_str(), strerror(errno));
        return false;
    }

    out.resize(size);

    #if defined(_LARGEFILE64_SOURCE) || defined(__ANDROID__)
        off64_t offset = static_cast<off64_t>(addr);
        if (lseek64(fd, offset, SEEK_SET) != offset) {
            LOGE("lseek64 failed for address 0x%llx: %s",
                 (unsigned long long)addr, strerror(errno));
            close(fd);
            return false;
        }
    #else
        off_t offset = static_cast<off_t>(addr);
        if (lseek(fd, offset, SEEK_SET) != offset) {
            LOGE("lseek failed for address 0x%llx: %s",
                 (unsigned long long)addr, strerror(errno));
            close(fd);
            return false;
        }
    #endif

    ssize_t total_read = 0;
    while (total_read < (ssize_t)size) {
        ssize_t n = read(fd, out.data() + total_read, size - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (total_read > 0) {
                out.resize(total_read);
                close(fd);
                return true;
            }
            close(fd);
            return false;
        }
        if (n == 0) break;
        total_read += n;
    }

    out.resize(total_read);
    close(fd);
    return total_read > 0;
}

bool ProcessMemory::dump_region(const MemoryRegion& region, std::vector<uint8_t>& out) const {
    if (!region.is_readable) {
        LOGW("Region 0x%llx-0x%llx is not readable, skipping", 
             (unsigned long long)region.start, (unsigned long long)region.end);
        return false;
    }

    LOGI("Dumping region 0x%llx-0x%llx (%s) %s", 
         (unsigned long long)region.start, (unsigned long long)region.end,
         region.perms.c_str(), region.pathname.c_str());

    return read_memory(region.start, region.size(), out);
}

bool ProcessMemory::dump_library(const std::string& lib_name, const std::string& output_path) const {
    auto regions = find_library_regions(lib_name);

    // If not found by exact name, try partial matches
    if (regions.empty()) {
        LOGI("'%s' not found by exact name, trying partial matches...", lib_name.c_str());

        // Try without .so extension
        auto name_without_ext = lib_name;
        if (name_without_ext.size() > 3 && name_without_ext.substr(name_without_ext.size()-3) == ".so") {
            name_without_ext = name_without_ext.substr(0, name_without_ext.size()-3);
        }

        regions = find_regions_by_partial_name(name_without_ext);

        // Also try "il2cpp" alone
        if (regions.empty() && lib_name.find("il2cpp") != std::string::npos) {
            regions = find_regions_by_partial_name("il2cpp");
        }
    }

    if (regions.empty()) {
        LOGE("Library '%s' not found in process memory", lib_name.c_str());

        // Show ALL libraries, not just .so
        LOGI("All file-backed mappings in memory:");
        int shown = 0;
        for (const auto& r : regions_) {
            if (!r.pathname.empty() && r.pathname[0] == '/' && r.pathname.find(".so") != std::string::npos) {
                LOGI("  %s", r.pathname.c_str());
                if (++shown >= 30) {
                    LOGI("  ... (%zu more)", regions_.size() - shown);
                    break;
                }
            }
        }
        if (shown == 0) {
            LOGI("  (no .so files with absolute paths found)");
        }

        // Also show anon mappings that might be il2cpp
        LOGI("Anonymous/anon mappings that might contain il2cpp:");
        shown = 0;
        for (const auto& r : regions_) {
            if (r.pathname.find("[anon") != std::string::npos || 
                r.pathname.find("[stack") != std::string::npos ||
                r.pathname.find("[heap") != std::string::npos) {
                if (r.is_executable) {
                    LOGI("  0x%llx-0x%llx %s %s",
                         (unsigned long long)r.start, (unsigned long long)r.end,
                         r.perms.c_str(), r.pathname.c_str());
                    if (++shown >= 10) break;
                }
            }
        }

        return false;
    }

    LOGI("Found %zu regions for '%s'", regions.size(), lib_name.c_str());

    auto sorted = regions;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.start < b.start;
    });

    uint64_t base_addr = UINT64_MAX;
    for (const auto& r : sorted) {
        if (r.offset == 0 && (r.is_executable || r.pathname.find(lib_name) != std::string::npos)) {
            base_addr = r.start;
            break;
        }
    }
    if (base_addr == UINT64_MAX) {
        base_addr = sorted[0].start;
    }

    LOGI("Library base address: 0x%llx", (unsigned long long)base_addr);

    uint64_t min_addr = sorted[0].start;
    uint64_t max_addr = sorted.back().end;
    size_t total_size = max_addr - min_addr;

    LOGI("Total memory range: 0x%llx - 0x%llx (%zu bytes)",
         (unsigned long long)min_addr, (unsigned long long)max_addr, total_size);

    std::vector<uint8_t> dump(total_size, 0);

    for (const auto& region : sorted) {
        if (!region.is_readable) {
            LOGW("Skipping non-readable region 0x%llx-0x%llx", 
                 (unsigned long long)region.start, (unsigned long long)region.end);
            continue;
        }

        std::vector<uint8_t> region_data;
        if (!read_memory(region.start, region.size(), region_data)) {
            LOGW("Failed to read region 0x%llx-0x%llx", 
                 (unsigned long long)region.start, (unsigned long long)region.end);
            continue;
        }

        size_t offset_in_dump = region.start - min_addr;
        if (offset_in_dump + region_data.size() <= dump.size()) {
            memcpy(dump.data() + offset_in_dump, region_data.data(), region_data.size());
        }

        LOGI("Dumped %zu bytes from 0x%llx", region_data.size(), 
             (unsigned long long)region.start);
    }

    if (dump.size() >= sizeof(Elf64_Ehdr)) {
        auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(dump.data());
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            LOGI("Fixing ELF64 headers...");
            if (ehdr->e_phoff > 0 && ehdr->e_phnum > 0) {
                auto* phdrs = reinterpret_cast<Elf64_Phdr*>(dump.data() + ehdr->e_phoff);
                for (int i = 0; i < ehdr->e_phnum; i++) {
                    if (phdrs[i].p_type == PT_LOAD) {
                        uint64_t old_vaddr = phdrs[i].p_vaddr;
                        if (old_vaddr >= base_addr) {
                            phdrs[i].p_vaddr = old_vaddr - base_addr;
                        }
                        phdrs[i].p_offset = phdrs[i].p_vaddr;
                    }
                }
            }
        } else if (dump.size() >= sizeof(Elf32_Ehdr)) {
            auto* ehdr32 = reinterpret_cast<Elf32_Ehdr*>(dump.data());
            if (memcmp(ehdr32->e_ident, ELFMAG, SELFMAG) == 0) {
                LOGI("Fixing ELF32 headers...");
                if (ehdr32->e_phoff > 0 && ehdr32->e_phnum > 0) {
                    auto* phdrs32 = reinterpret_cast<Elf32_Phdr*>(dump.data() + ehdr32->e_phoff);
                    for (int i = 0; i < ehdr32->e_phnum; i++) {
                        if (phdrs32[i].p_type == PT_LOAD) {
                            uint32_t old_vaddr = phdrs32[i].p_vaddr;
                            if (old_vaddr >= base_addr) {
                                phdrs32[i].p_vaddr = old_vaddr - base_addr;
                            }
                            phdrs32[i].p_offset = phdrs32[i].p_vaddr;
                        }
                    }
                }
            }
        }
    }

    if (!utils::write_file(output_path, dump)) {
        LOGE("Failed to write dump to %s", output_path.c_str());
        return false;
    }

    LOGI("Library dumped to: %s (%zu bytes)", output_path.c_str(), dump.size());
    return true;
}

bool ProcessMemory::dump_metadata(const std::string& output_path) const {
    auto regions = find_file_regions("global-metadata.dat");
    if (regions.empty()) {
        regions = find_file_regions("metadata");
    }

    if (regions.empty()) {
        LOGE("global-metadata.dat not found in process memory");
        return false;
    }

    const auto& region = regions[0];
    std::vector<uint8_t> data;

    if (!dump_region(region, data)) {
        return false;
    }

    if (data.size() >= 8) {
        uint32_t sanity = *reinterpret_cast<uint32_t*>(data.data());
        if (sanity != 0xFAB11BAF) {
            LOGW("Metadata sanity check failed (0x%08X), might be encrypted", sanity);
        } else {
            LOGI("Metadata sanity check passed");
        }
    }

    if (!utils::write_file(output_path, data)) {
        return false;
    }

    LOGI("Metadata dumped to: %s (%zu bytes)", output_path.c_str(), data.size());
    return true;
}
