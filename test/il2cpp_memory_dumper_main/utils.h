#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <cstring>
#include <algorithm>

#define LOGD(fmt, ...) printf("[D] " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[W] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E] " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[I] " fmt "\n", ##__VA_ARGS__)

namespace utils {

// Read entire file into memory
std::vector<uint8_t> read_file(const std::string& path);

// Write memory buffer to file
bool write_file(const std::string& path, const uint8_t* data, size_t size);
bool write_file(const std::string& path, const std::vector<uint8_t>& data);

// Find PID by process name (searches /proc)
pid_t find_pid_by_name(const std::string& name);

// Check if running as root
bool is_root();

// Hex string to uint64_t
uint64_t hex_to_u64(const std::string& str);

// Trim string
std::string trim(const std::string& s);

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delim);

} // namespace utils
