#include "RwxScanner.h"

void RwxScanner::clear() {
    region_history_.clear();
}

DWORD RwxScanner::simple_crc32(const BYTE* data, const size_t size) const {
    DWORD crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; ++i) { crc ^= data[i]; for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ (0xEDB88320 & -static_cast<int>(crc & 1)); } return ~crc;
}

std::string RwxScanner::protection_to_string(const DWORD protect) const {
    switch (protect) {
    case PAGE_EXECUTE: return "X"; case PAGE_EXECUTE_READ: return "RX"; case PAGE_EXECUTE_READWRITE: return "RWX"; case PAGE_EXECUTE_WRITECOPY: return "XWC";
    case PAGE_NOACCESS: return "NO ACCESS"; case PAGE_READONLY: return "R"; case PAGE_READWRITE: return "RW"; case PAGE_WRITECOPY: return "WC";
    default:
        std::string base_prot = "UNKNOWN";
        if (protect & PAGE_EXECUTE_READWRITE) base_prot = "RWX";
        else if (protect & PAGE_EXECUTE_READ) base_prot = "RX";
        else if (protect & PAGE_READWRITE) base_prot = "RW";
        return base_prot + " (...)";
    }
}

void RwxScanner::get_module_owner_ex(HANDLE hProcess, void* addr, const std::vector<BYTE>& region_data, char* buffer, size_t buffer_size) const {
    if (GetMappedFileNameA(hProcess, addr, buffer, (DWORD)buffer_size)) {
        char* filename = PathFindFileNameA(buffer);
        strcpy_s(buffer, buffer_size, filename);
    }
    else {
        if (region_data.size() > 0x40 && region_data[0] == 'M' && region_data[1] == 'Z') {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)region_data.data();
            if (pDosHeader->e_lfanew < region_data.size()) {
                PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(region_data.data() + pDosHeader->e_lfanew);
                if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    strcpy_s(buffer, buffer_size, "[Manually Mapped PE]");
                    return;
                }
            }
        }
        strcpy_s(buffer, buffer_size, "[Private Memory]");
    }
}

std::string RwxScanner::analyze_for_heuristics(const std::vector<BYTE>& data) const {
    std::string findings;
    const BYTE peb_lookup_64[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };
    if (std::search(data.begin(), data.end(), std::begin(peb_lookup_64), std::end(peb_lookup_64)) != data.end()) {
        findings += "PEB Lookup; ";
    }
    if (findings.empty()) return "N/A";
    return findings;
}

void RwxScanner::scan_and_post_results(HWND hTargetWnd, HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t addr = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    const uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < maxAddr && VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            std::ostringstream region_stream;
            region_stream << std::hex << mbi.BaseAddress << "-" << (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
            const std::string region_str = region_stream.str();

            std::vector<BYTE> page_data(mbi.RegionSize);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, page_data.data(), mbi.RegionSize, &bytes_read) && bytes_read > 0) {
                page_data.resize(bytes_read);
                const DWORD current_crc = simple_crc32(page_data.data(), bytes_read);

                auto it = region_history_.find(region_str);
                bool is_new = it == region_history_.end();
                bool has_changed = !is_new && it->second.last_crc32 != current_crc;
                bool protection_changed = !is_new && it->second.last_protection != mbi.Protect;

                if (is_new || has_changed || protection_changed) {
                    ScanResult* result = new ScanResult();
                    result->base_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                    result->region_size = mbi.RegionSize;
                    result->current_data = page_data;

                    if (is_new) {
                        strcpy_s(result->status, "New");
                    }
                    else {
                        result->previous_data = it->second.last_data;
                        if (protection_changed) {
                            std::string old_prot_str = protection_to_string(it->second.last_protection);
                            std::string new_prot_str = protection_to_string(mbi.Protect);
                            sprintf_s(result->status, "Prot Change: %s -> %s", old_prot_str.c_str(), new_prot_str.c_str());
                        }
                        else {
                            strcpy_s(result->status, "Changed");
                        }
                    }

                    region_history_[region_str] = { current_crc, mbi.Protect, page_data };

                    auto now = std::chrono::system_clock::now();
                    auto time_now = std::chrono::system_clock::to_time_t(now);
                    std::tm tm_buf;
                    localtime_s(&tm_buf, &time_now);
                    strftime(result->timestamp, sizeof(result->timestamp), "%T", &tm_buf);
                    strcpy_s(result->region, region_str.c_str());

                    std::ostringstream size_stream;
                    size_stream << mbi.RegionSize / 1024 << " KB";
                    strcpy_s(result->size, size_stream.str().c_str());

                    strcpy_s(result->protection, protection_to_string(mbi.Protect).c_str());
                    get_module_owner_ex(hProcess, mbi.BaseAddress, page_data, result->module, MAX_PATH);
                    result->heuristic_results = analyze_for_heuristics(page_data);

                    PostMessage(hTargetWnd, WM_APP_ADD_ITEM, 0, (LPARAM)result);
                }
            }
        }
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
}