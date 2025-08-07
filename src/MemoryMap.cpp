#include "WindowProcedures.h"
#include "Globals.h"

namespace MemMapHelpers {
    std::wstring StateToString(DWORD state) {
        switch (state) {
        case MEM_COMMIT:  return L"Commit";
        case MEM_RESERVE: return L"Reserve";
        case MEM_FREE:    return L"Free";
        default:          return L"Unknown";
        }
    }
    std::wstring TypeToString(DWORD type) {
        switch (type) {
        case MEM_IMAGE:   return L"Image";
        case MEM_MAPPED:  return L"Mapped";
        case MEM_PRIVATE: return L"Private";
        default:          return L"";
        }
    }
    std::wstring ProtectionToString(DWORD protect, DWORD state) {
        if (state == MEM_RESERVE) return L"--- [Reserved]";
        if (protect == 0 || state == MEM_FREE) return L"";
        std::string s;
        if (protect & PAGE_NOACCESS) s = "---";
        else if (protect & PAGE_READONLY) s = "R--";
        else if (protect & PAGE_READWRITE) s = "RW-";
        else if (protect & PAGE_WRITECOPY) s = "RWC";
        else if (protect & PAGE_EXECUTE) s = "--X";
        else if (protect & PAGE_EXECUTE_READ) s = "R-X";
        else if (protect & PAGE_EXECUTE_READWRITE) s = "RWX";
        else if (protect & PAGE_EXECUTE_WRITECOPY) s = "RWC";
        else s = "???";
        if (protect & PAGE_GUARD) s += "G";
        if (protect & PAGE_NOCACHE) s += "N";
        if (protect & PAGE_WRITECOMBINE) s += "W";
        return std::wstring(s.begin(), s.end());
    }
}

LRESULT CALLBACK MemMapWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hListView;
    switch (msg) {
    case WM_CREATE: {
        hListView = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
            0, 0, 0, 0,
            hWnd, (HMENU)1, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        const wchar_t* headers[] = { L"Address", L"Size", L"State", L"Protection", L"Type", L"Details" };
        int widths[] = { 130, 80, 70, 120, 70, 350 };
        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (int i = 0; i < 6; ++i) {
            lvc.iSubItem = i;
            lvc.pszText = (LPWSTR)headers[i];
            lvc.cx = widths[i];
            ListView_InsertColumn(hListView, i, &lvc);
        }

        if (!g_hTargetProcess) {
            LVITEMW lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = 0;
            lvi.pszText = (LPWSTR)L"No process attached. Please attach to a process first.";
            ListView_InsertItem(hListView, &lvi);
            break;
        }

        SendMessage(hListView, WM_SETREDRAW, FALSE, 0);

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t addr = 0;
        const uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
        int itemIndex = 0;

        while (addr < maxAddr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(g_hTargetProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            wchar_t szAddress[20];
            swprintf_s(szAddress, L"0x%p", mbi.BaseAddress);
            wchar_t szSize[20];
            if (mbi.RegionSize < 1024) swprintf_s(szSize, L"%llu B", (unsigned long long)mbi.RegionSize);
            else swprintf_s(szSize, L"%llu K", (unsigned long long)mbi.RegionSize / 1024);

            std::wstring state = MemMapHelpers::StateToString(mbi.State);
            std::wstring protection = MemMapHelpers::ProtectionToString(mbi.Protect, mbi.State);
            std::wstring type = L"";
            wchar_t details[MAX_PATH] = { 0 };

            if (mbi.State != MEM_FREE) {
                type = MemMapHelpers::TypeToString(mbi.Type);
                if (GetMappedFileNameW(g_hTargetProcess, mbi.BaseAddress, details, MAX_PATH)) {
                    PathStripPathW(details);
                }
                else {
                    if (mbi.Type == MEM_IMAGE) wcscpy_s(details, MAX_PATH, L"Image (path unavailable)");
                    else if (mbi.Type == MEM_PRIVATE) wcscpy_s(details, MAX_PATH, L"Private Data");
                }
            }
            else {
                wcscpy_s(details, MAX_PATH, L"Free Space");
            }

            LVITEMW lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = itemIndex;
            lvi.pszText = szAddress;
            ListView_InsertItem(hListView, &lvi);

            ListView_SetItemText(hListView, itemIndex, 1, szSize);
            ListView_SetItemText(hListView, itemIndex, 2, (LPWSTR)state.c_str());
            ListView_SetItemText(hListView, itemIndex, 3, (LPWSTR)protection.c_str());
            ListView_SetItemText(hListView, itemIndex, 4, (LPWSTR)type.c_str());
            ListView_SetItemText(hListView, itemIndex, 5, details);

            itemIndex++;
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hListView, NULL, TRUE);
        break;
    }
    case WM_SIZE: {
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);
        MoveWindow(hListView, 0, 0, rcClient.right, rcClient.bottom, TRUE);
        break;
    }
    case WM_CLOSE: {
        DestroyWindow(hWnd);
        break;
    }
    case WM_DESTROY: {
        g_hMemMapWnd = NULL;
        break;
    }
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}