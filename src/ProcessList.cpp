#include "WindowProcedures.h"
#include "Globals.h"

LRESULT CALLBACK ProcListWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HWND hListView = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
            10, 10, 360, 400, hWnd, (HMENU)ID_PROC_LIST_VIEW, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.pszText = (LPWSTR)L"Process Name";
        lvc.cx = 240;
        ListView_InsertColumn(hListView, 0, &lvc);
        lvc.pszText = (LPWSTR)L"PID";
        lvc.cx = 100;
        ListView_InsertColumn(hListView, 1, &lvc);

        DWORD aProcesses[1024], cbNeeded;
        if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
            DWORD cProcesses = cbNeeded / sizeof(DWORD);
            for (unsigned int i = 0; i < cProcesses; i++) {
                if (aProcesses[i] != 0) {
                    wchar_t szProcessName[MAX_PATH] = L"<unknown>";
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
                    if (hProcess != NULL) {
                        HMODULE hMod;
                        DWORD cbNeeded2;
                        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                            GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(wchar_t));
                        }
                        CloseHandle(hProcess);
                    }
                    LVITEMW lvi = { 0 };
                    lvi.mask = LVIF_TEXT | LVIF_PARAM;
                    lvi.iItem = i;
                    lvi.pszText = szProcessName;
                    lvi.lParam = (LPARAM)aProcesses[i];
                    int newIndex = ListView_InsertItem(hListView, &lvi);

                    wchar_t pidStr[16];
                    swprintf_s(pidStr, L"%d", aProcesses[i]);
                    ListView_SetItemText(hListView, newIndex, 1, pidStr);
                }
            }
        }

        CreateWindowW(L"BUTTON", L"OK", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 200, 420, 80, 25, hWnd, (HMENU)ID_BTN_PROC_OK, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        CreateWindowW(L"BUTTON", L"Cancel", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 290, 420, 80, 25, hWnd, (HMENU)ID_BTN_PROC_CANCEL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BTN_PROC_OK: {
            HWND hListView = GetDlgItem(hWnd, ID_PROC_LIST_VIEW);
            int iSelected = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
            if (iSelected != -1) {
                LVITEMW lvi = { 0 };
                lvi.mask = LVIF_PARAM;
                lvi.iItem = iSelected;
                ListView_GetItem(hListView, &lvi);
                DWORD pid = (DWORD)lvi.lParam;
                PostMessage(g_hMainWnd, WM_APP_PROCESS_SELECTED, (WPARAM)pid, 0);
                DestroyWindow(hWnd);
            }
            else {
                MessageBoxW(hWnd, L"Please select a process.", L"Information", MB_OK | MB_ICONINFORMATION);
            }
            break;
        }
        case ID_BTN_PROC_CANCEL: {
            DestroyWindow(hWnd);
            break;
        }
        }
        break;
    }
    case WM_CLOSE: {
        DestroyWindow(hWnd);
        break;
    }
    case WM_DESTROY: {
        g_hProcListWnd = NULL;
        break;
    }
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}