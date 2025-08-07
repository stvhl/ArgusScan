#include "WindowProcedures.h"
#include "Globals.h"

void AddIatHookItem(HWND hListView, int& index, const wchar_t* module, const char* api,
    const wchar_t* expected, const wchar_t* actual, const wchar_t* status)
{
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = index++;
    lvi.pszText = (LPWSTR)module;
    int newIdx = ListView_InsertItem(hListView, &lvi);

    wchar_t api_w[256];
    MultiByteToWideChar(CP_ACP, 0, api, -1, api_w, 256);
    ListView_SetItemText(hListView, newIdx, 1, api_w);
    ListView_SetItemText(hListView, newIdx, 2, (LPWSTR)expected);
    ListView_SetItemText(hListView, newIdx, 3, (LPWSTR)actual);
    ListView_SetItemText(hListView, newIdx, 4, (LPWSTR)status);
}

void ScanAndDisplayIatHooks(HWND hListView, HANDLE hProcess) {
    SendMessage(hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hListView);

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
        return;
    }

    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);
    int itemIndex = 0;

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        wchar_t szModName[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
            continue;
        }
        PathStripPathW(szModName);

        BYTE headers[4096];
        if (!ReadProcessMemory(hProcess, hMods[i], headers, sizeof(headers), NULL)) {
            continue;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)headers;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS32 pNtHeader32 = (PIMAGE_NT_HEADERS32)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_NT_HEADERS64 pNtHeader64 = (PIMAGE_NT_HEADERS64)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

        if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        IMAGE_DATA_DIRECTORY importDirectory;
        if (isWow64) { // 32-bit process
            importDirectory = pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
        else { // 64-bit process
            importDirectory = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }

        if (importDirectory.VirtualAddress == 0) {
            continue;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) new BYTE[importDirectory.Size];
        if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + importDirectory.VirtualAddress), importDesc, importDirectory.Size, NULL)) {
            delete[] importDesc;
            continue;
        }

        for (PIMAGE_IMPORT_DESCRIPTOR pImportDesc = importDesc; pImportDesc->Name != 0; pImportDesc++) {
            char dllName[MAX_PATH];
            if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + pImportDesc->Name), dllName, sizeof(dllName), NULL)) {
                continue;
            }

            HMODULE hLocalModule = LoadLibraryA(dllName);
            if (!hLocalModule) {
                continue;
            }

            uintptr_t thunkRVA = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
            uintptr_t iatRVA = pImportDesc->FirstThunk;
            if (thunkRVA == 0 || iatRVA == 0) {
                FreeLibrary(hLocalModule);
                continue;
            }

            int thunkIndex = 0;
            while (true) {
                uintptr_t funcNameRVA = 0;
                uintptr_t funcAddress = 0;

                if (isWow64) {
                    IMAGE_THUNK_DATA32 thunkData;
                    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + thunkRVA + (thunkIndex * sizeof(IMAGE_THUNK_DATA32))), &thunkData, sizeof(thunkData), NULL) || thunkData.u1.AddressOfData == 0) break;
                    funcNameRVA = thunkData.u1.AddressOfData;

                    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + iatRVA + (thunkIndex * sizeof(IMAGE_THUNK_DATA32))), &funcAddress, sizeof(uintptr_t), NULL)) break;
                }
                else {
                    IMAGE_THUNK_DATA64 thunkData;
                    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + thunkRVA + (thunkIndex * sizeof(IMAGE_THUNK_DATA64))), &thunkData, sizeof(thunkData), NULL) || thunkData.u1.AddressOfData == 0) break;
                    funcNameRVA = thunkData.u1.AddressOfData;

                    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + iatRVA + (thunkIndex * sizeof(IMAGE_THUNK_DATA64))), &funcAddress, sizeof(uintptr_t), NULL)) break;
                }

                char funcName[256] = "<By Ordinal>";
                if (!(funcNameRVA & (isWow64 ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64))) {
                    IMAGE_IMPORT_BY_NAME importByName;
                    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hMods[i] + funcNameRVA), &importByName, sizeof(importByName), NULL)) {
                        thunkIndex++; continue;
                    }
                    strncpy_s(funcName, (char*)importByName.Name, sizeof(funcName) - 1);
                }

                FARPROC expectedAddress = GetProcAddress(hLocalModule, funcName);
                if (expectedAddress && (uintptr_t)expectedAddress != funcAddress) {
                    wchar_t expectedStr[20], actualStr[20], statusStr[MAX_PATH];
                    swprintf_s(expectedStr, L"0x%p", expectedAddress);
                    swprintf_s(actualStr, L"0x%p", (void*)funcAddress);

                    MEMORY_BASIC_INFORMATION mbi;
                    wchar_t hookOwner[MAX_PATH] = L"[Unknown Memory]";
                    if (VirtualQueryEx(hProcess, (LPCVOID)funcAddress, &mbi, sizeof(mbi))) {
                        if (mbi.Type == MEM_IMAGE) {
                            GetModuleFileNameExW(hProcess, (HMODULE)mbi.AllocationBase, hookOwner, MAX_PATH);
                            PathStripPathW(hookOwner);
                        }
                        else {
                            wcscpy_s(hookOwner, L"[Private/Mapped Memory]");
                        }
                    }
                    swprintf_s(statusStr, L"HOOKED! -> %s", hookOwner);
                    AddIatHookItem(hListView, itemIndex, szModName, funcName, expectedStr, actualStr, statusStr);
                }

                thunkIndex++;
            }
            FreeLibrary(hLocalModule);
        }
        delete[] importDesc;
    }
    SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hListView, NULL, TRUE);
}


LRESULT CALLBACK IatHookWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hListView;
    switch (msg) {
    case WM_CREATE: {
        hListView = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        const wchar_t* headers[] = { L"Module", L"API", L"Expected Location", L"Actual Location", L"Status / Hooked By" };
        int widths[] = { 120, 200, 140, 140, 250 };
        LVCOLUMNW lvc = { 0 }; lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        for (int i = 0; i < 5; ++i) { lvc.pszText = (LPWSTR)headers[i]; lvc.cx = widths[i]; ListView_InsertColumn(hListView, i, &lvc); }

        if (g_hTargetProcess) {
            SetWindowTextW(hWnd, L"IAT Hook Scan - Scanning...");
            ScanAndDisplayIatHooks(hListView, g_hTargetProcess);
            SetWindowTextW(hWnd, L"IAT Hook Scan - Completed");
        }
        else {
            LVITEMW lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = 0;
            lvi.pszText = (LPWSTR)L"No process attached. Please attach to a process first.";
            ListView_InsertItem(hListView, &lvi);
        }
        break;
    }
    case WM_NOTIFY: {
        LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
        if (lplvcd->nmcd.hdr.code == NM_CUSTOMDRAW) {
            if (lplvcd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (lplvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                wchar_t statusText[MAX_PATH];
                ListView_GetItemText(hListView, lplvcd->nmcd.dwItemSpec, 4, statusText, MAX_PATH);
                if (wcsstr(statusText, L"HOOKED!")) {
                    lplvcd->clrTextBk = RGB(255, 200, 200); // Highlight hooked in red
                }
                return CDRF_DODEFAULT;
            }
        }
        break;
    }
    case WM_SIZE: {
        RECT rcClient; GetClientRect(hWnd, &rcClient);
        MoveWindow(hListView, 0, 0, rcClient.right, rcClient.bottom, TRUE);
        break;
    }
    case WM_CLOSE: DestroyWindow(hWnd); break;
    case WM_DESTROY: g_hIatHookWnd = NULL; break;
    default: return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}