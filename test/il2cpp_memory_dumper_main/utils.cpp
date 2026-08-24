#include "utils.h"
#include <fcntl.h>
#include <errno.h>

namespace utils {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return {};
    }
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

bool write_file(const std::string& path, const uint8_t* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data), size);
    return file.good();
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    return write_file(path, data.data(), data.size());
}

// Read process cmdline
static std::string read_cmdline(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::string cmdline;
    std::getline(file, cmdline);
    // cmdline uses null separators, take only first component
    size_t null_pos = cmdline.find('\0');
    if (null_pos != std::string::npos) {
        cmdline = cmdline.substr(0, null_pos);
    }
    return cmdline;
}

// Read process name from /proc/PID/status
static std::string read_process_name(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("Name:") == 0) {
            return trim(line.substr(5));
        }
    }
    return "";
}

pid_t find_pid_by_name(const std::string& name) {
    // First try: exact match of first component of cmdline
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    pid_t best_match = -1;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;

        auto cmdline = read_cmdline(static_cast<pid_t>(pid));
        if (cmdline.empty()) continue;

        // Extract basename from cmdline
        size_t last_slash = cmdline.find_last_of('/');
        std::string basename = (last_slash != std::string::npos) 
            ? cmdline.substr(last_slash + 1) 
            : cmdline;

        // Exact match on basename
        if (basename == name) {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }

        // Exact match on full cmdline
        if (cmdline == name) {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }

        // Contains match (fallback, only if no exact match found)
        if (best_match < 0 && cmdline.find(name) != std::string::npos) {
            best_match = static_cast<pid_t>(pid);
        }
    }

    closedir(dir);
    return best_match;
}

bool is_root() {
    return geteuid() == 0;
}

uint64_t hex_to_u64(const std::string& str) {
    if (str.empty()) return 0;
    try {
        size_t pos = 0;
        while (pos < str.size() && (str[pos] == ' ' || str[pos] == '\t')) pos++;
        if (pos >= str.size()) return 0;

        if (pos + 2 < str.size() && str[pos] == '0' && (str[pos+1] == 'x' || str[pos+1] == 'X')) {
            pos += 2;
        }

        return std::stoull(str.substr(pos), nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) {
        if (!token.empty()) tokens.push_back(token);
    }
    return tokens;
}

} // namespace utils
