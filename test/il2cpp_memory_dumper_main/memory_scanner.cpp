#include "memory_scanner.h"
#include "utils.h"
#include <elf.h>
#include <cstring>

MemoryScanner::MemoryScanner(const ProcessMemory& mem) : mem_(mem) {}

bool MemoryScanner::read_safe(uint64_t addr, size_t size, std::vector<uint8_t>& out) const {
    out.clear();

    const MemoryRegion* target_region = nullptr;
    for (const auto& region : mem_.regions()) {
        if (addr >= region.start && addr + size <= region.end) {
            if (region.is_readable) {
                target_region = &region;
                break;
            }
            return false;
        }
    }

    if (!target_region) {
        return false;
    }

    std::string mem_path = "/proc/" + std::to_string(mem_.pid()) + "/mem";
    int fd = open(mem_path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    out.resize(size);

    #if defined(_LARGEFILE64_SOURCE) || defined(__ANDROID__)
        off64_t offset = static_cast<off64_t>(addr);
        if (lseek64(fd, offset, SEEK_SET) != offset) {
            close(fd);
            return false;
        }
    #else
        off_t offset = static_cast<off_t>(addr);
        if (lseek(fd, offset, SEEK_SET) != offset) {
            close(fd);
            return false;
        }
    #endif

    ssize_t total = 0;
    while (total < (ssize_t)size) {
        ssize_t n = read(fd, out.data() + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        total += n;
    }

    out.resize(total);
    close(fd);
    return total > 0;
}

std::vector<MemoryScanner::ElfMatch> MemoryScanner::scan_for_elf_headers() const {
    std::vector<ElfMatch> results;

    LOGI("Scanning memory for ELF headers...");
    int scanned = 0;
    int found = 0;

    for (const auto& region : mem_.regions()) {
        if (!region.is_readable) continue;
        if (region.size() < 4) continue;
        if (region.size() < 4096) continue;

        scanned++;

        std::vector<uint8_t> header;
        if (!read_safe(region.start, 32, header)) continue;
        if (header.size() < 4) continue;

        if (header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
            bool is64 = (header.size() > EI_CLASS && header[EI_CLASS] == ELFCLASS64);

            ElfMatch match{};
            match.addr = region.start;
            match.is64bit = is64;

            if (is64 && header.size() >= sizeof(Elf64_Ehdr)) {
                auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(header.data());
                match.size_hint = ehdr->e_entry;
            } else if (!is64 && header.size() >= sizeof(Elf32_Ehdr)) {
                auto* ehdr32 = reinterpret_cast<Elf32_Ehdr*>(header.data());
                match.size_hint = ehdr32->e_entry;
            }

            results.push_back(match);
            found++;

            LOGI("Found ELF %s at 0x%llx (region: %s, size: %zu)",
                 is64 ? "64-bit" : "32-bit",
                 (unsigned long long)region.start,
                 region.pathname.c_str(),
                 region.size());
        }
    }

    LOGI("Scanned %d regions, found %d ELF headers", scanned, found);
    return results;
}

std::vector<MemoryScanner::MetadataMatch> MemoryScanner::scan_for_metadata() const {
    std::vector<MetadataMatch> results;

    LOGI("Scanning memory for IL2CPP metadata (sanity 0xFAB11BAF)...");
    int scanned = 0;
    int found = 0;

    for (const auto& region : mem_.regions()) {
        if (!region.is_readable) continue;
        if (region.size() < 8) continue;

        scanned++;

        std::vector<uint8_t> header;
        if (!read_safe(region.start, 8, header)) continue;
        if (header.size() < 8) continue;

        uint32_t sanity = *reinterpret_cast<uint32_t*>(header.data());
        if (sanity == 0xFAB11BAF) {
            uint32_t version = *reinterpret_cast<uint32_t*>(header.data() + 4);

            MetadataMatch match{};
            match.addr = region.start;
            match.version = version;
            match.size_hint = region.size();

            results.push_back(match);
            found++;

            LOGI("Found metadata v%d at 0x%llx (region: %s, size: %zu)",
                 version,
                 (unsigned long long)region.start,
                 region.pathname.c_str(),
                 region.size());
        }
    }

    LOGI("Scanned %d regions, found %d metadata headers", scanned, found);
    return results;
}

size_t MemoryScanner::estimate_metadata_size(const uint8_t* header) const {
    const uint32_t* fields = reinterpret_cast<const uint32_t*>(header);
    uint32_t max_offset = 0;

    // Scan header fields to find largest offset
    for (int i = 2; i < 60; i += 2) {
        uint32_t off = fields[i];
        uint32_t cnt = fields[i+1];
        if (off + cnt * 4 > max_offset) {
            max_offset = off + cnt * 4;
        }
    }

    return max_offset > 1024*1024 ? max_offset : 50*1024*1024;
}

std::vector<MemoryScanner::MetadataMatch> MemoryScanner::scan_region_for_metadata(const MemoryRegion& region) const {
    std::vector<MetadataMatch> results;

    if (!region.is_readable || region.size() < 1024) return results;

    const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
    const size_t OVERLAP = 4; // bytes to overlap between chunks

    for (size_t offset = 0; offset < region.size(); offset += CHUNK_SIZE - OVERLAP) {
        size_t read_size = std::min(CHUNK_SIZE, region.size() - offset);

        std::vector<uint8_t> chunk;
        if (!read_safe(region.start + offset, read_size, chunk)) continue;

        for (size_t i = 0; i + 4 <= chunk.size(); i++) {
            if (chunk[i] == 0xAF && chunk[i+1] == 0x1B && 
                chunk[i+2] == 0xB1 && chunk[i+3] == 0xFA) {

                uint64_t found_addr = region.start + offset + i;

                // Read full header
                uint32_t version = 0;
                if (i + 8 <= chunk.size()) {
                    version = *reinterpret_cast<uint32_t*>(&chunk[i+4]);
                } else {
                    std::vector<uint8_t> ver_buf;
                    if (read_safe(found_addr + 4, 4, ver_buf) && ver_buf.size() == 4) {
                        version = *reinterpret_cast<uint32_t*>(ver_buf.data());
                    }
                }

                MetadataMatch match{};
                match.addr = found_addr;
                match.version = version;
                match.size_hint = region.size() - (offset + i);

                results.push_back(match);

                LOGI("DEEP SCAN: Found metadata v%d at 0x%llx (region: %s)",
                     version,
                     (unsigned long long)found_addr,
                     region.pathname.c_str());
            }
        }
    }

    return results;
}

std::vector<MemoryScanner::MetadataMatch> MemoryScanner::deep_scan_for_metadata() const {
    std::vector<MetadataMatch> results;

    LOGI("=== DEEP SCANNING ALL MEMORY FOR METADATA ===");
    LOGI("This may take a while...");

    int regions_scanned = 0;
    int total_found = 0;

    for (const auto& region : mem_.regions()) {
        if (!region.is_readable) continue;
        if (region.size() < 1024*1024) continue; // Skip tiny regions for speed

        regions_scanned++;

        auto found = scan_region_for_metadata(region);
        for (auto& match : found) {
            results.push_back(match);
            total_found++;
        }

        if (regions_scanned % 10 == 0) {
            LOGI("Progress: scanned %d regions, found %d metadata so far", 
                 regions_scanned, total_found);
        }
    }

    LOGI("Deep scan complete: %d regions scanned, %d metadata found", 
         regions_scanned, total_found);

    return results;
}

std::vector<MemoryScanner::Il2CppApiMatch> MemoryScanner::find_il2cpp_api(
    uint64_t module_base, size_t module_size) const {

    std::vector<Il2CppApiMatch> results;

    // ARM64 function signatures for common IL2CPP functions
    // These are prologue patterns (first 16 bytes)
    struct SigPattern {
        const char* name;
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask; // 0xFF = must match, 0x00 = ignore
    };

    std::vector<SigPattern> patterns = {
        // il2cpp_init: stp x29,x30,[sp,#-16]! ; mov x29,sp ; sub sp,sp,#N
        {"il2cpp_init", {0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91}, 
                        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},

        // il2cpp_class_from_name: stp x29,x30,[sp,#-48]! ; mov x29,sp
        {"il2cpp_class_from_name", {0xFD, 0x7B, 0xBD, 0xA9, 0xFD, 0x03, 0x00, 0x91},
                                  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},

        // il2cpp_string_new: stp x29,x30,[sp,#-16]! ; mov x29,sp
        {"il2cpp_string_new", {0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91},
                             {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},

        // il2cpp_domain_get: simple function, often just returns global
        {"il2cpp_domain_get", {0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91},
                             {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    };

    LOGI("Scanning for IL2CPP API signatures in module at 0x%llx...", 
         (unsigned long long)module_base);

    const size_t SCAN_CHUNK = 1024 * 1024; // 1MB

    for (size_t offset = 0; offset < module_size; offset += SCAN_CHUNK) {
        size_t chunk_size = std::min(SCAN_CHUNK, module_size - offset);

        std::vector<uint8_t> chunk;
        if (!read_safe(module_base + offset, chunk_size, chunk)) continue;

        for (const auto& pat : patterns) {
            size_t sig_len = pat.bytes.size();

            for (size_t i = 0; i + sig_len <= chunk.size(); i += 4) { // 4-byte aligned
                bool match = true;
                for (size_t j = 0; j < sig_len; j++) {
                    if (pat.mask[j] == 0xFF && chunk[i+j] != pat.bytes[j]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    uint64_t addr = module_base + offset + i;

                    // Check if already found
                    bool already = false;
                    for (const auto& existing : results) {
                        if (existing.name == pat.name || std::abs((long long)(existing.addr - addr)) < 16) {
                            already = true;
                            break;
                        }
                    }

                    if (!already) {
                        Il2CppApiMatch api_match{};
                        api_match.addr = addr;
                        api_match.name = pat.name;
                        api_match.signature = pat.bytes;
                        results.push_back(api_match);

                        LOGI("Found %s at 0x%llx", pat.name, (unsigned long long)addr);
                    }
                }
            }
        }
    }

    LOGI("Found %zu IL2CPP API functions", results.size());
    return results;
}

std::vector<MemoryRegion> MemoryScanner::find_large_anon_executable() const {
    std::vector<MemoryRegion> results;

    LOGI("Looking for large anonymous executable regions...");

    for (const auto& region : mem_.regions()) {
        if (!region.is_executable) continue;
        if (!region.pathname.empty() && region.pathname[0] == '/') continue;
        if (region.size() < 1024 * 1024) continue;

        results.push_back(region);

        LOGI("Candidate: 0x%llx-0x%llx (%s) %s (%zu MB)",
             (unsigned long long)region.start,
             (unsigned long long)region.end,
             region.perms.c_str(),
             region.pathname.c_str(),
             region.size() / (1024 * 1024));
    }

    LOGI("Found %d large anonymous executable regions", (int)results.size());
    return results;
}

bool MemoryScanner::dump_elf_by_scan(const std::string& output_path, uint64_t& out_base) const {
    auto matches = scan_for_elf_headers();

    if (matches.empty()) {
        LOGE("No ELF headers found in memory");
        return false;
    }

    const ElfMatch* best = nullptr;
    uint64_t best_size = 0;

    for (const auto& match : matches) {
        for (const auto& region : mem_.regions()) {
            if (match.addr >= region.start && match.addr < region.end) {
                if (region.size() > best_size) {
                    best_size = region.size();
                    best = &match;
                    out_base = region.start;
                }
                break;
            }
        }
    }

    if (!best) {
        LOGE("Could not determine best ELF match");
        return false;
    }

    LOGI("Selected ELF at 0x%llx (%s, region size: %zu MB)",
         (unsigned long long)best->addr,
         best->is64bit ? "64-bit" : "32-bit",
         best_size / (1024 * 1024));

    std::vector<MemoryRegion> regions_to_dump;
    uint64_t current_end = out_base;

    for (const auto& region : mem_.regions()) {
        if (region.start == current_end || region.start == out_base) {
            regions_to_dump.push_back(region);
            current_end = region.end;
        }
    }

    if (regions_to_dump.empty()) {
        for (const auto& region : mem_.regions()) {
            if (best->addr >= region.start && best->addr < region.end) {
                regions_to_dump.push_back(region);
                break;
            }
        }
    }

    uint64_t min_addr = regions_to_dump[0].start;
    uint64_t max_addr = regions_to_dump.back().end;
    size_t total_size = max_addr - min_addr;

    LOGI("Dumping %zu regions, total size: %zu bytes", regions_to_dump.size(), total_size);

    std::vector<uint8_t> dump(total_size, 0);

    for (const auto& region : regions_to_dump) {
        if (!region.is_readable) continue;

        std::vector<uint8_t> region_data;
        if (!read_safe(region.start, region.size(), region_data)) {
            LOGW("Failed to read region 0x%llx-0x%llx", 
                 (unsigned long long)region.start, (unsigned long long)region.end);
            continue;
        }

        size_t offset = region.start - min_addr;
        if (offset + region_data.size() <= dump.size()) {
            memcpy(dump.data() + offset, region_data.data(), region_data.size());
        }
    }

    if (dump.size() >= sizeof(Elf64_Ehdr)) {
        auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(dump.data());
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            if (ehdr->e_phoff > 0 && ehdr->e_phnum > 0) {
                auto* phdrs = reinterpret_cast<Elf64_Phdr*>(dump.data() + ehdr->e_phoff);
                for (int i = 0; i < ehdr->e_phnum; i++) {
                    if (phdrs[i].p_type == PT_LOAD) {
                        uint64_t old_vaddr = phdrs[i].p_vaddr;
                        if (old_vaddr >= out_base) {
                            phdrs[i].p_vaddr = old_vaddr - out_base;
                        }
                        phdrs[i].p_offset = phdrs[i].p_vaddr;
                    }
                }
            }
        }
    }

    if (!utils::write_file(output_path, dump)) {
        LOGE("Failed to write dump");
        return false;
    }

    LOGI("ELF dumped to: %s (%zu bytes)", output_path.c_str(), dump.size());
    return true;
}

bool MemoryScanner::dump_metadata_by_scan(const std::string& output_path) const {
    auto matches = scan_for_metadata();

    if (matches.empty()) {
        LOGE("No metadata found in memory");
        return false;
    }

    const MetadataMatch* best = nullptr;
    uint64_t best_size = 0;

    for (const auto& match : matches) {
        if (match.size_hint > best_size) {
            best_size = match.size_hint;
            best = &match;
        }
    }

    if (!best) {
        LOGE("Could not select best metadata match");
        return false;
    }

    LOGI("Selected metadata v%d at 0x%llx (size: %zu)",
         best->version,
         (unsigned long long)best->addr,
         best->size_hint);

    std::vector<uint8_t> data;
    if (!read_safe(best->addr, best->size_hint, data)) {
        LOGE("Failed to read metadata");
        return false;
    }

    if (!utils::write_file(output_path, data)) {
        return false;
    }

    LOGI("Metadata dumped to: %s (%zu bytes)", output_path.c_str(), data.size());
    return true;
}

bool MemoryScanner::deep_dump_metadata(const std::string& output_path) const {
    auto matches = deep_scan_for_metadata();

    if (matches.empty()) {
        LOGE("No metadata found in deep scan");
        return false;
    }

    LOGI("Found %zu metadata candidates, dumping all...", matches.size());

    bool any_dumped = false;
    for (size_t i = 0; i < matches.size(); i++) {
        const auto& match = matches[i];

        // Read header to estimate size
        std::vector<uint8_t> header;
        if (!read_safe(match.addr, 256, header) || header.size() < 256) continue;

        size_t dump_size = estimate_metadata_size(header.data());

        // Cap at region size or 100MB
        dump_size = std::min(dump_size, (size_t)match.size_hint);
        dump_size = std::min(dump_size, (size_t)(100 * 1024 * 1024));

        std::string path = output_path;
        if (matches.size() > 1) {
            path = output_path + "_" + std::to_string(i) + "_v" + std::to_string(match.version);
        }

        std::vector<uint8_t> data;
        if (!read_safe(match.addr, dump_size, data)) continue;

        if (utils::write_file(path, data)) {
            LOGI("Dumped metadata %zu/%zu: %s (%zu bytes, v%d at 0x%llx)",
                 i+1, matches.size(), path.c_str(), data.size(), 
                 match.version, (unsigned long long)match.addr);
            any_dumped = true;
        }
    }

    return any_dumped;
}
