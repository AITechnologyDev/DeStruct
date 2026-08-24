#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include "utils.h"
#include "memory_map.h"
#include "memory_scanner.h"
#include "elf_fixer.h"

void print_usage(const char* prog) {
    std::cerr << R"(
╔══════════════════════════════════════════════════════════════════╗
║         IL2CPP Memory Dumper - Standalone Binary                 ║
║         Extract libil2cpp.so & metadata from running process     ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  )" << prog << R"( <command> [options]

Commands:
  dump-lib       - Dump libil2cpp.so from process memory (by name)
  dump-meta      - Dump global-metadata.dat from process memory (by name)
  dump-all       - Dump both lib and metadata (by name)
  scan-lib       - Scan memory for ELF and dump (for packed/encrypted libs)
  scan-meta      - Scan memory for metadata sanity bytes and dump
  deep-scan      - DEEP scan ALL memory for metadata (slow but thorough)
  scan-all       - Scan and dump both lib and metadata
  find-api       - Find IL2CPP API functions in libunity.so
  list           - List memory regions of process

Options:
  -p, --pid <pid>         Process PID (required if --package not used)
  -n, --package <name>    Process name/package to search for
  -o, --output <path>     Output directory (default: ./dump)
  --fix-elf               Fix ELF headers after dump (recommended)
  --no-fix                Skip ELF fixing
  -h, --help              Show this help

Examples:
  # For normal (unprotected) games:
  )" << prog << R"( dump-all -p 1234 -o ./mygame

  # For protected/packed games (Standoff 2, PUBG, etc.):
  )" << prog << R"( scan-all -p 1234 -o ./mygame
  )" << prog << R"( deep-scan -p 1234 -o ./mygame

  # Find IL2CPP API in libunity.so:
  )" << prog << R"( find-api -p 1234

  # List memory regions
  )" << prog << R"( list -p 1234

Note: Root access required on Android!
Tip: Use 'pidof com.yourgame.package' to find PID
)";
}

enum class Command {
    NONE,
    DUMP_LIB,
    DUMP_META,
    DUMP_ALL,
    SCAN_LIB,
    SCAN_META,
    DEEP_SCAN,
    SCAN_ALL,
    FIND_API,
    LIST
};

struct Args {
    Command cmd = Command::NONE;
    pid_t pid = -1;
    std::string package_name;
    std::string output_dir = "./dump";
    bool fix_elf = true;
};

static uint64_t safe_hex_parse(const char* str) {
    if (!str || !*str) return 0;
    try {
        while (*str && (*str == ' ' || *str == '\t')) str++;
        if (!*str) return 0;
        return std::stoull(str, nullptr, 0);
    } catch (...) {
        return 0;
    }
}

bool parse_args(int argc, char* argv[], Args& args) {
    if (argc < 2) return false;

    std::string cmd_str = argv[1];
    if (cmd_str == "dump-lib") args.cmd = Command::DUMP_LIB;
    else if (cmd_str == "dump-meta") args.cmd = Command::DUMP_META;
    else if (cmd_str == "dump-all") args.cmd = Command::DUMP_ALL;
    else if (cmd_str == "scan-lib") args.cmd = Command::SCAN_LIB;
    else if (cmd_str == "scan-meta") args.cmd = Command::SCAN_META;
    else if (cmd_str == "deep-scan") args.cmd = Command::DEEP_SCAN;
    else if (cmd_str == "scan-all") args.cmd = Command::SCAN_ALL;
    else if (cmd_str == "find-api") args.cmd = Command::FIND_API;
    else if (cmd_str == "list") args.cmd = Command::LIST;
    else if (cmd_str == "-h" || cmd_str == "--help") return false;
    else {
        std::cerr << "Unknown command: " << cmd_str << "\n";
        return false;
    }

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) && i + 1 < argc) {
            try {
                args.pid = std::stoi(argv[++i]);
            } catch (...) {
                LOGE("Invalid PID: %s", argv[i]);
                return false;
            }
        }
        else if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--package") == 0) && i + 1 < argc) {
            args.package_name = argv[++i];
        }
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            args.output_dir = argv[++i];
        }
        else if (strcmp(argv[i], "--fix-elf") == 0) {
            args.fix_elf = true;
        }
        else if (strcmp(argv[i], "--no-fix") == 0) {
            args.fix_elf = false;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            return false;
        }
    }

    return true;
}

static std::string get_process_cmdline(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream file(path);
    if (!file.is_open()) return "(unknown)";
    std::string cmdline;
    std::getline(file, cmdline);
    size_t null_pos = cmdline.find('\0');
    if (null_pos != std::string::npos) {
        cmdline = cmdline.substr(0, null_pos);
    }
    return cmdline.empty() ? "(empty)" : cmdline;
}

int main(int argc, char* argv[]) {
    Args args;
    if (!parse_args(argc, argv, args)) {
        print_usage(argv[0]);
        return 1;
    }

    LOGI("========================================");
    LOGI("IL2CPP Memory Dumper v2.0 (Enhanced)");
    LOGI("========================================");

    if (!utils::is_root()) {
        LOGW("Not running as root! Memory access may fail.");
        LOGW("On Android: run with 'su -c \"%s ...\"'", argv[0]);
    }

    // Resolve PID
    if (args.pid < 0) {
        if (args.package_name.empty()) {
            LOGE("Either --pid or --package must be specified");
            return 1;
        }

        LOGI("Searching for process: %s", args.package_name.c_str());
        args.pid = utils::find_pid_by_name(args.package_name);

        if (args.pid < 0) {
            LOGE("Process not found: %s", args.package_name.c_str());
            LOGI("Tip: Use 'pidof %s' or 'ps -A | grep %s' to find PID", 
                 args.package_name.c_str(), args.package_name.c_str());
            return 1;
        }

        LOGI("Found PID: %d", args.pid);
    }

    auto cmdline = get_process_cmdline(args.pid);
    LOGI("Target process cmdline: %s", cmdline.c_str());

    if (cmdline.find("il2cpp_memory_dumper") != std::string::npos) {
        LOGW("WARNING: Target process appears to be this dumper itself!");
        LOGW("Use 'pidof <game_package>' to find the correct PID.");
    }

    std::string mkdir_cmd = "mkdir -p " + args.output_dir;
    system(mkdir_cmd.c_str());

    ProcessMemory mem(args.pid);
    if (!mem.parse_maps()) {
        LOGE("Failed to parse memory maps");
        return 1;
    }

    MemoryScanner scanner(mem);

    switch (args.cmd) {
        case Command::LIST: {
            LOGI("Memory regions:");
            for (const auto& region : mem.regions()) {
                if (!region.pathname.empty()) {
                    printf("  0x%012llx-0x%012llx %s %s\n",
                           (unsigned long long)region.start,
                           (unsigned long long)region.end,
                           region.perms.c_str(),
                           region.pathname.c_str());
                }
            }
            break;
        }

        case Command::FIND_API: {
            LOGI("=== Finding IL2CPP API in libunity.so ===");
            auto unity_regions = mem.find_library_regions("libunity.so");
            if (unity_regions.empty()) {
                LOGE("libunity.so not found in memory");
                return 1;
            }

            uint64_t base = unity_regions[0].start;
            uint64_t end = unity_regions.back().end;
            size_t size = end - base;

            LOGI("libunity.so: 0x%llx - 0x%llx (%zu MB)",
                 (unsigned long long)base, (unsigned long long)end,
                 size / (1024*1024));

            auto apis = scanner.find_il2cpp_api(base, size);

            LOGI("\nFound %zu IL2CPP API functions:", apis.size());
            for (const auto& api : apis) {
                printf("  %-30s @ 0x%llx\n", api.name.c_str(), (unsigned long long)api.addr);
            }

            if (!apis.empty()) {
                LOGI("\nYou can use these addresses for manual hooking.");
            }
            break;
        }

        case Command::DUMP_LIB: {
            std::string out_path = args.output_dir + "/libil2cpp_dumped.so";
            if (!mem.dump_library("libil2cpp.so", out_path)) {
                LOGE("Failed to dump library by name. Try 'scan-lib' for protected games.");
                return 1;
            }

            if (args.fix_elf) {
                std::string fixed_path = args.output_dir + "/libil2cpp_fixed.so";
                auto regions = mem.find_library_regions("libil2cpp.so");
                uint64_t base = regions.empty() ? 0 : regions[0].start;
                ElfFixer::fix_elf(out_path, fixed_path, base);
            }
            break;
        }

        case Command::DUMP_META: {
            std::string out_path = args.output_dir + "/global-metadata.dat";
            if (!mem.dump_metadata(out_path)) {
                LOGE("Failed to dump metadata by name. Try 'scan-meta' or 'deep-scan'.");
                return 1;
            }
            break;
        }

        case Command::DUMP_ALL: {
            std::string lib_path = args.output_dir + "/libil2cpp_dumped.so";
            if (!mem.dump_library("libil2cpp.so", lib_path)) {
                LOGE("Failed to dump library. Try 'scan-all' for protected games.");
                return 1;
            }

            if (args.fix_elf) {
                std::string fixed_path = args.output_dir + "/libil2cpp_fixed.so";
                auto regions = mem.find_library_regions("libil2cpp.so");
                uint64_t base = regions.empty() ? 0 : regions[0].start;
                ElfFixer::fix_elf(lib_path, fixed_path, base);
            }

            std::string meta_path = args.output_dir + "/global-metadata.dat";
            mem.dump_metadata(meta_path);
            break;
        }

        case Command::SCAN_LIB: {
            std::string out_path = args.output_dir + "/libil2cpp_scanned.so";
            uint64_t base = 0;
            if (!scanner.dump_elf_by_scan(out_path, base)) {
                LOGE("Failed to find and dump ELF");
                return 1;
            }

            if (args.fix_elf) {
                std::string fixed_path = args.output_dir + "/libil2cpp_fixed.so";
                ElfFixer::fix_elf(out_path, fixed_path, base);
            }
            break;
        }

        case Command::SCAN_META: {
            std::string out_path = args.output_dir + "/global-metadata_scanned.dat";
            if (!scanner.dump_metadata_by_scan(out_path)) {
                LOGE("Failed to find and dump metadata");
                return 1;
            }
            break;
        }

        case Command::DEEP_SCAN: {
            LOGI("=== DEEP SCAN MODE ===");
            LOGI("This will scan ALL readable memory for metadata signature.");
            LOGI("It may take several minutes depending on process size.\n");

            std::string out_path = args.output_dir + "/global-metadata_deep.dat";
            if (!scanner.deep_dump_metadata(out_path)) {
                LOGE("Deep scan failed to find metadata");
                LOGI("Possible reasons:");
                LOGI("  - Metadata is encrypted and not decrypted in memory");
                LOGI("  - Metadata was decrypted but already freed");
                LOGI("  - Game uses custom metadata format");
                LOGI("  - Try running this during game loading (not main menu)");
                return 1;
            }
            break;
        }

        case Command::SCAN_ALL: {
            LOGI("=== Scanning for ELF (libil2cpp.so) ===");
            std::string lib_path = args.output_dir + "/libil2cpp_scanned.so";
            uint64_t base = 0;
            bool lib_ok = scanner.dump_elf_by_scan(lib_path, base);

            if (lib_ok && args.fix_elf) {
                std::string fixed_path = args.output_dir + "/libil2cpp_fixed.so";
                ElfFixer::fix_elf(lib_path, fixed_path, base);
            }

            LOGI("=== Scanning for metadata ===");
            std::string meta_path = args.output_dir + "/global-metadata_scanned.dat";
            bool meta_ok = scanner.dump_metadata_by_scan(meta_path);

            LOGI("========================================");
            if (lib_ok) {
                LOGI("Library dumped: %s", lib_path.c_str());
                if (args.fix_elf) {
                    LOGI("Fixed library: %s/libil2cpp_fixed.so", args.output_dir.c_str());
                }
            } else {
                LOGE("Library dump failed");
            }

            if (meta_ok) {
                LOGI("Metadata dumped: %s", meta_path.c_str());
            } else {
                LOGW("Metadata dump failed (might be encrypted)");
                LOGI("Tip: Try 'deep-scan' command for thorough search");
            }

            if (lib_ok) {
                LOGI("Next: Run Il2CppDumper with the dumped files");
            }
            LOGI("========================================");
            break;
        }

        default:
            break;
    }

    return 0;
}
