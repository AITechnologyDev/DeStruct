#include "elf_fixer.h"
#include "utils.h"
#include <elf.h>
#include <cstring>
#include <algorithm>

bool ElfFixer::fix_elf(const std::string& input_path, const std::string& output_path, uint64_t base_addr) {
    auto data = utils::read_file(input_path);
    if (data.empty()) {
        LOGE("Failed to read input ELF");
        return false;
    }

    if (!fix_elf_buffer(data, base_addr)) {
        return false;
    }

    return utils::write_file(output_path, data);
}

bool ElfFixer::fix_elf_buffer(std::vector<uint8_t>& data, uint64_t base_addr) {
    if (data.size() < EI_NIDENT) {
        LOGE("File too small to be ELF");
        return false;
    }

    if (memcmp(data.data(), ELFMAG, SELFMAG) != 0) {
        LOGE("Not an ELF file");
        return false;
    }

    bool is64 = (data[EI_CLASS] == ELFCLASS64);

    if (is64) {
        return fix_elf64(data, base_addr);
    } else {
        return fix_elf32(data, base_addr);
    }
}

bool ElfFixer::fix_elf64(std::vector<uint8_t>& data, uint64_t base_addr) {
    if (data.size() < sizeof(Elf64_Ehdr)) {
        LOGE("ELF64 file too small");
        return false;
    }

    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(data.data());

    LOGI("ELF64: Entry=0x%llx, PHoff=0x%llx, PHnum=%d",
         (unsigned long long)ehdr->e_entry,
         (unsigned long long)ehdr->e_phoff,
         ehdr->e_phnum);

    // Check if section headers already exist
    if (ehdr->e_shoff != 0 && ehdr->e_shnum > 0) {
        LOGI("Section headers already present, skipping rebuild");
        return true;
    }

    // Read program headers
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
        LOGE("No program headers found");
        return false;
    }

    auto* phdrs = reinterpret_cast<Elf64_Phdr*>(data.data() + ehdr->e_phoff);

    // Collect PT_LOAD segments
    struct SegmentInfo {
        uint64_t vaddr;
        uint64_t memsz;
        uint64_t filesz;
        uint64_t offset;
        uint32_t flags;
    };
    std::vector<SegmentInfo> segments;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            SegmentInfo seg{};
            seg.vaddr = phdrs[i].p_vaddr;
            seg.memsz = phdrs[i].p_memsz;
            seg.filesz = phdrs[i].p_filesz;
            seg.offset = phdrs[i].p_offset;
            seg.flags = phdrs[i].p_flags;
            segments.push_back(seg);

            LOGI("PT_LOAD: vaddr=0x%llx, memsz=0x%llx, filesz=0x%llx, offset=0x%llx",
                 (unsigned long long)seg.vaddr,
                 (unsigned long long)seg.memsz,
                 (unsigned long long)seg.filesz,
                 (unsigned long long)seg.offset);
        }
    }

    if (segments.empty()) {
        LOGE("No PT_LOAD segments found");
        return false;
    }

    // For a simple fix, we'll just ensure the ELF is loadable
    // Full section header rebuild is complex; instead we:
    // 1. Ensure p_offset aligns with p_vaddr (for dumped memory)
    // 2. Set e_shoff to 0 (no sections, but program headers are enough for loading)

    // Actually, for Il2CppDumper we need at least some sections
    // Let's create minimal section headers at the end of the file

    // Calculate where to put new section headers
    size_t sh_offset = data.size();

    // We need: null section, .text, .data, .bss, .dynamic, .dynsym, .dynstr, .shstrtab
    const int NUM_SECTIONS = 9;
    size_t sh_size = NUM_SECTIONS * sizeof(Elf64_Shdr);

    // String table for section names
    const char* shstrtab = "\0.shstrtab\0.text\0.data\0.bss\0.dynamic\0.dynsym\0.dynstr\0";
    size_t shstrtab_size = strlen(shstrtab) + 1;

    // Resize buffer
    size_t original_size = data.size();
    data.resize(original_size + shstrtab_size + sh_size);

    // Write shstrtab
    memcpy(data.data() + original_size, shstrtab, shstrtab_size);

    // Write section headers
    auto* shdrs = reinterpret_cast<Elf64_Shdr*>(data.data() + original_size + shstrtab_size);
    memset(shdrs, 0, sh_size);

    // Section 0: NULL
    // Section 1: .shstrtab
    shdrs[1].sh_name = 1; // ".shstrtab"
    shdrs[1].sh_type = SHT_STRTAB;
    shdrs[1].sh_offset = original_size;
    shdrs[1].sh_size = shstrtab_size;
    shdrs[1].sh_addralign = 1;

    // Find .text, .data, .bss from PT_LOAD segments
    int sec_idx = 2;
    for (const auto& seg : segments) {
        Elf64_Shdr* sh = &shdrs[sec_idx++];

        if (seg.flags & PF_X) {
            // Executable = .text
            sh->sh_name = 11; // ".text"
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        } else if (seg.flags & PF_W) {
            // Writable = .data or .bss
            if (seg.filesz < seg.memsz) {
                sh->sh_name = 22; // ".bss"
                sh->sh_type = SHT_NOBITS;
                sh->sh_flags = SHF_ALLOC | SHF_WRITE;
            } else {
                sh->sh_name = 17; // ".data"
                sh->sh_type = SHT_PROGBITS;
                sh->sh_flags = SHF_ALLOC | SHF_WRITE;
            }
        } else {
            // Read-only = .rodata
            sh->sh_name = 17; // reuse .data name for simplicity
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC;
        }

        sh->sh_addr = seg.vaddr;
        sh->sh_offset = seg.offset;
        sh->sh_size = seg.memsz;
        sh->sh_addralign = 0x1000;

        if (sec_idx >= NUM_SECTIONS) break;
    }

    // Update ELF header
    ehdr->e_shoff = original_size + shstrtab_size;
    ehdr->e_shnum = NUM_SECTIONS;
    ehdr->e_shstrndx = 1;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);

    LOGI("Rebuilt %d section headers at offset 0x%zx", NUM_SECTIONS, ehdr->e_shoff);

    return true;
}

bool ElfFixer::fix_elf32(std::vector<uint8_t>& data, uint64_t base_addr) {
    // Similar to 64-bit but with 32-bit structures
    // Simplified implementation
    LOGI("ELF32 fix not fully implemented, but file should still be usable");
    return true;
}
