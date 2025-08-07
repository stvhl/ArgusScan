#pragma once
#include "framework.h"

class RwxScanner {
public:
    struct ScanResult {
        char timestamp[32];
        char region[64];
        char size[32];
        char protection[32];
        char module[MAX_PATH];
        char status[64];
        uintptr_t base_address;
        size_t region_size;
        std::vector<BYTE> previous_data;
        std::vector<BYTE> current_data;
        std::string heuristic_results;
    };

    void clear();
    void scan_and_post_results(HWND hTargetWnd, HANDLE hProcess);

private:
    struct RegionInfo {
        DWORD last_crc32;
        DWORD last_protection;
        std::vector<BYTE> last_data;
    };
    std::unordered_map<std::string, RegionInfo> region_history_;

    DWORD simple_crc32(const BYTE* data, size_t size) const;
    std::string protection_to_string(const DWORD protect) const;
    void get_module_owner_ex(HANDLE hProcess, void* addr, const std::vector<BYTE>& region_data, char* buffer, size_t buffer_size) const;
    std::string analyze_for_heuristics(const std::vector<BYTE>& data) const;
};