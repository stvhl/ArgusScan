#include "WindowProcedures.h"
#include "Globals.h"

LRESULT CALLBACK ThreadsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hListView;
    switch (msg) {
    case WM_CREATE: {
        hListView = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT, 0, 0, 0, 0, hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        const wchar_t* headers[] = { L"TID", L"Start Address", L"Location", L"Status" };
        int widths[] = { 60, 140, 400, 200 };
        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        for (int i = 0; i < 4; ++i) {
            lvc.pszText = (LPWSTR)headers[i];
            lvc.cx = widths[i];
            ListView_InsertColumn(hListView, i, &lvc);
        }

        if (!g_hTargetProcess) break;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) break;

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        int itemIndex = 0;
        if (Thread32First(hSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == g_dwTargetPid) {
                    wchar_t tidStr[16], addrStr[20], locationStr[MAX_PATH] = L"N/A", statusStr[100] = L"";

                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                    PVOID startAddress = NULL;
                    if (hThread) {
                        using NtQueryInformationThread_t = NTSTATUS(WINAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
                        auto pfnNtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

                        if (pfnNtQueryInformationThread) {
                            pfnNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(PVOID), NULL);
                        }
                        CloseHandle(hThread);
                    }

                    MEMORY_BASIC_INFORMATION mbi;
                    if (startAddress != NULL && VirtualQueryEx(g_hTargetProcess, startAddress, &mbi, sizeof(mbi))) {
                        if (mbi.Type == MEM_IMAGE) {
                            GetMappedFileNameW(g_hTargetProcess, mbi.BaseAddress, locationStr, MAX_PATH);
                            PathStripPathW(locationStr);
                            wsprintfW(statusStr, L"OK - In module");
                        }
                        else {
                            wsprintfW(statusStr, L"Suspicious - Not in a module!");
                            wcscpy_s(locationStr, L"[Private/Mapped Memory]");
                        }
                    }
                    else {
                        wcscpy_s(statusStr, L"Start address unknown");
                    }

                    wsprintfW(tidStr, L"%d", te32.th32ThreadID);
                    wsprintfW(addrStr, L"0x%p", startAddress);

                    LVITEMW lvi = { 0 };
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = itemIndex;
                    lvi.pszText = tidStr;
                    int newIdx = ListView_InsertItem(hListView, &lvi);
                    ListView_SetItemText(hListView, newIdx, 1, addrStr);
                    ListView_SetItemText(hListView, newIdx, 2, locationStr);
                    ListView_SetItemText(hListView, newIdx, 3, statusStr);
                    itemIndex++;
                }
            } while (Thread32Next(hSnap, &te32));
        }
        CloseHandle(hSnap);
        break;
    }
    case WM_SIZE: {
        RECT rcClient; GetClientRect(hWnd, &rcClient);
        MoveWindow(hListView, 0, 0, rcClient.right, rcClient.bottom, TRUE);
        break;
    }
    case WM_CLOSE: DestroyWindow(hWnd); break;
    case WM_DESTROY: g_hThreadsWnd = NULL; break;
    default: return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}