#include "WindowProcedures.h"
#include "Globals.h"
#include "Disassembly.h"

void ClearListViewItems(HWND hListView) {
    int count = ListView_GetItemCount(hListView);
    for (int i = 0; i < count; i++) {
        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_PARAM;
        lvi.iItem = i;
        if (ListView_GetItem(hListView, &lvi) && lvi.lParam != NULL) {
            delete (RwxScanner::ScanResult*)lvi.lParam;
        }
    }
    ListView_DeleteAllItems(hListView);
}

void CreateControls(HWND hWnd, HINSTANCE hInstance) {
    g_hAttachBtn = CreateWindowW(L"BUTTON", L"Attach to Process...", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 10, 10, 140, 30, hWnd, (HMENU)ID_BTN_ATTACH, hInstance, NULL);
    g_hStartBtn = CreateWindowW(L"BUTTON", L"Scan", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 160, 10, 70, 30, hWnd, (HMENU)ID_BTN_START, hInstance, NULL);
    g_hStopBtn = CreateWindowW(L"BUTTON", L"Stop", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 240, 10, 70, 30, hWnd, (HMENU)ID_BTN_STOP, hInstance, NULL);
    g_hShowMapBtn = CreateWindowW(L"BUTTON", L"Memory Map", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 320, 10, 100, 30, hWnd, (HMENU)ID_BTN_SHOW_MAP, hInstance, NULL);
    g_hThreadsBtn = CreateWindowW(L"BUTTON", L"Threads", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 430, 10, 90, 30, hWnd, (HMENU)ID_BTN_THREADS, hInstance, NULL);
    g_hIatHooksBtn = CreateWindowW(L"BUTTON", L"IAT Hooks", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 530, 10, 90, 30, hWnd, (HMENU)ID_BTN_IAT_HOOKS, hInstance, NULL);
    g_hSaveBtn = CreateWindowW(L"BUTTON", L"Save...", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 630, 10, 80, 30, hWnd, (HMENU)ID_BTN_SAVE, hInstance, NULL);
    g_hLoadBtn = CreateWindowW(L"BUTTON", L"Load...", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 720, 10, 80, 30, hWnd, (HMENU)ID_BTN_LOAD, hInstance, NULL);

    EnableWindow(g_hStartBtn, FALSE);
    EnableWindow(g_hStopBtn, FALSE);
    EnableWindow(g_hShowMapBtn, FALSE);
    EnableWindow(g_hThreadsBtn, FALSE);
    EnableWindow(g_hIatHooksBtn, FALSE);
    EnableWindow(g_hSaveBtn, FALSE);

    g_hListView = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
        10, 50, 940, 500, hWnd, (HMENU)ID_LIST_VIEW, hInstance, NULL);
    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    const wchar_t* headers[] = { L"Time", L"Status", L"Region (Address)", L"Size", L"Protection", L"Module", L"Heuristics" };
    int widths[] = { 80, 150, 180, 70, 80, 200, 150 };
    for (int i = 0; i < 7; ++i) { lvc.iSubItem = i; lvc.pszText = (LPWSTR)headers[i]; lvc.cx = widths[i]; ListView_InsertColumn(g_hListView, i, &lvc); }
}

DWORD WINAPI ScanThread(LPVOID lpParam) {
    HWND hWnd = (HWND)lpParam;
    while (g_bIsScanning) {
        if (g_hTargetProcess) {
            g_scanner.scan_and_post_results(hWnd, g_hTargetProcess);
        }
        Sleep(1000);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hMainWnd = hWnd;
        CreateControls(hWnd, ((LPCREATESTRUCT)lParam)->hInstance);
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BTN_ATTACH: {
            if (g_hProcListWnd && IsWindow(g_hProcListWnd)) { SetForegroundWindow(g_hProcListWnd); }
            else { g_hProcListWnd = CreateWindowExW(WS_EX_TOPMOST, PROC_LIST_CLASS_NAME, L"Attach to Process", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 400, 500, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE), NULL); if (g_hProcListWnd) { ShowWindow(g_hProcListWnd, SW_SHOW); } }
            break;
        }
        case ID_BTN_START: {
            if (!g_bIsScanning && g_hTargetProcess != NULL) {
                g_scanner.clear();
                ClearListViewItems(g_hListView);
                g_bIsScanning = true;
                g_hScanThread = CreateThread(NULL, 0, ScanThread, hWnd, 0, NULL);
                EnableWindow(g_hAttachBtn, FALSE); EnableWindow(g_hStartBtn, FALSE); EnableWindow(g_hStopBtn, TRUE); EnableWindow(g_hLoadBtn, FALSE);
            }
            break;
        }
        case ID_BTN_STOP: {
            if (g_bIsScanning) {
                g_bIsScanning = false;
                if (g_hScanThread != NULL) { WaitForSingleObject(g_hScanThread, 2000); CloseHandle(g_hScanThread); g_hScanThread = NULL; }
                EnableWindow(g_hAttachBtn, TRUE); EnableWindow(g_hStartBtn, TRUE); EnableWindow(g_hStopBtn, FALSE); EnableWindow(g_hLoadBtn, TRUE);
            }
            break;
        }
        case ID_BTN_SHOW_MAP: {
            if (g_hMemMapWnd && IsWindow(g_hMemMapWnd)) { SetForegroundWindow(g_hMemMapWnd); }
            else { g_hMemMapWnd = CreateWindowW(MEMORY_MAP_CLASS_NAME, L"Process Memory Map", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE), NULL); }
            break;
        }
        case ID_BTN_THREADS: {
            if (g_hThreadsWnd && IsWindow(g_hThreadsWnd)) SetForegroundWindow(g_hThreadsWnd);
            else g_hThreadsWnd = CreateWindowW(THREADS_CLASS_NAME, L"Process Threads", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 400, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE), NULL);
            break;
        }
        case ID_BTN_IAT_HOOKS: {
            if (g_hIatHookWnd && IsWindow(g_hIatHookWnd)) SetForegroundWindow(g_hIatHookWnd);
            else g_hIatHookWnd = CreateWindowW(IAT_HOOK_CLASS_NAME, L"IAT Hook Scan", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE), NULL);
            break;
        }
        case ID_BTN_SAVE: {
            wchar_t filename[MAX_PATH] = { 0 };
            OPENFILENAMEW ofn = { 0 };
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hWnd; ofn.lpstrFile = filename; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"Argus Scan (*.ascan)\0*.ascan\0All Files (*.*)\0*.*\0"; ofn.lpstrDefExt = L"ascan"; ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
            if (GetSaveFileNameW(&ofn)) {
                std::wofstream f(filename);
                if (!f.is_open()) { MessageBoxW(hWnd, L"Failed to open file for writing.", L"Error", MB_OK | MB_ICONERROR); break; }
                f << L"Timestamp;Status;Region;Size;Protection;Module;Heuristics\n";
                int count = ListView_GetItemCount(g_hListView);
                for (int i = 0; i < count; ++i) {
                    LVITEMW lvi = { 0 }; lvi.mask = LVIF_PARAM; lvi.iItem = i;
                    ListView_GetItem(g_hListView, &lvi);
                    RwxScanner::ScanResult* r = (RwxScanner::ScanResult*)lvi.lParam;
                    if (r) {
                        wchar_t line_buffer[1024];
                        swprintf_s(line_buffer, L"%hs;%hs;%hs;%hs;%hs;%hs;%hs\n", r->timestamp, r->status, r->region, r->size, r->protection, r->module, r->heuristic_results.c_str());
                        f << line_buffer;
                    }
                }
                MessageBoxW(hWnd, (std::wstring(L"Scan results saved to ") + filename).c_str(), L"Save Complete", MB_OK);
            }
            break;
        }
        case ID_BTN_LOAD: {
            if (g_bIsScanning) { MessageBoxW(hWnd, L"Cannot load results while a scan is active.", L"Warning", MB_OK | MB_ICONWARNING); break; }
            wchar_t filename[MAX_PATH] = { 0 };
            OPENFILENAMEW ofn = { 0 };
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hWnd; ofn.lpstrFile = filename; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"Argus Scan (*.ascan)\0*.ascan\0All Files (*.*)\0*.*\0"; ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                ClearListViewItems(g_hListView);
                std::wifstream f(filename); std::wstring line;
                if (!f.is_open()) { MessageBoxW(hWnd, L"Failed to open file for reading.", L"Error", MB_OK | MB_ICONERROR); break; }
                std::getline(f, line);
                while (std::getline(f, line)) {
                    std::wstringstream ss(line); std::wstring field;
                    RwxScanner::ScanResult* r = new RwxScanner::ScanResult();
                    char mb_buffer[MAX_PATH];

                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->timestamp, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->status, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->region, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->size, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->protection, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_ACP, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); strcpy_s(r->module, mb_buffer);
                    std::getline(ss, field, L';'); WideCharToMultiByte(CP_UTF8, 0, field.c_str(), -1, mb_buffer, sizeof(mb_buffer), NULL, NULL); r->heuristic_results = mb_buffer;

                    PostMessage(hWnd, WM_APP_ADD_ITEM, 0, (LPARAM)r);
                }
                SetWindowTextW(hWnd, (std::wstring(L"Argus Scanner - Loaded: ") + PathFindFileNameW(filename)).c_str());
                EnableWindow(g_hStartBtn, FALSE); EnableWindow(g_hAttachBtn, TRUE); EnableWindow(g_hStopBtn, FALSE);
            }
            break;
        }
        }
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->hwndFrom == g_hListView) {
            if (lpnmh->code == NM_DBLCLK) {
                LPNMITEMACTIVATE lpnmia = (LPNMITEMACTIVATE)lParam;
                if (lpnmia->iItem != -1 && g_hTargetProcess != NULL) {
                    LVITEMW lvi = { 0 }; lvi.mask = LVIF_PARAM; lvi.iItem = lpnmia->iItem;
                    ListView_GetItem(g_hListView, &lvi);
                    RwxScanner::ScanResult* result = (RwxScanner::ScanResult*)lvi.lParam;

                    if (result) {
                        DisassemblyParams* params = new DisassemblyParams();
                        params->baseAddress = result->base_address;
                        params->regionSize = result->region_size;
                        params->hProcess = g_hTargetProcess;
                        params->memoryBuffer = result->current_data;

                        if (g_hDisasmWnd && IsWindow(g_hDisasmWnd)) { DestroyWindow(g_hDisasmWnd); }
                        g_hDisasmWnd = CreateWindowExW(WS_EX_TOOLWINDOW, DISASM_CLASS_NAME, L"Disassembly", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE), params);
                    }
                }
            }
            else if (lpnmh->code == NM_CUSTOMDRAW) {
                LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
                if (lplvcd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
                if (lplvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    RwxScanner::ScanResult* r = (RwxScanner::ScanResult*)lplvcd->nmcd.lItemlParam;
                    if (r) {
                        if (strstr(r->protection, "RWX") != NULL) { lplvcd->clrTextBk = RGB(255, 200, 200); }
                        else if (strstr(r->module, "[Private Memory]") != NULL && (strstr(r->protection, "RX") != NULL || strstr(r->protection, "XWC") != NULL)) { lplvcd->clrTextBk = RGB(255, 255, 180); }
                        else if (strstr(r->status, "Changed") != NULL || strstr(r->status, "Prot Change") != NULL) { lplvcd->clrText = RGB(0, 0, 200); }
                    }
                    return CDRF_DODEFAULT;
                }
            }
        }
        break;
    }
    case WM_APP_PROCESS_SELECTED: {
        if (g_bIsScanning) { SendMessage(hWnd, WM_COMMAND, MAKEWPARAM(ID_BTN_STOP, 0), 0); }
        if (g_hTargetProcess) { CloseHandle(g_hTargetProcess); g_hTargetProcess = NULL; }

        g_dwTargetPid = (DWORD)wParam;
        const DWORD desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
        g_hTargetProcess = OpenProcess(desiredAccess, FALSE, g_dwTargetPid);

        if (g_hTargetProcess) {
            GetModuleBaseNameW(g_hTargetProcess, NULL, g_wszTargetProcessName, MAX_PATH);
            wchar_t newTitle[MAX_PATH + 50];
            swprintf_s(newTitle, L"Argus Scanner - Attached to %s (PID: %d)", g_wszTargetProcessName, g_dwTargetPid);
            SetWindowTextW(hWnd, newTitle);
            EnableWindow(g_hStartBtn, TRUE); EnableWindow(g_hShowMapBtn, TRUE); EnableWindow(g_hAttachBtn, TRUE); EnableWindow(g_hStopBtn, FALSE);
            EnableWindow(g_hThreadsBtn, TRUE); EnableWindow(g_hIatHooksBtn, TRUE); EnableWindow(g_hSaveBtn, TRUE); EnableWindow(g_hLoadBtn, TRUE);
        }
        else {
            MessageBoxW(hWnd, L"Failed to open the selected process. Try running as administrator.", L"Error", MB_OK | MB_ICONERROR);
            SetWindowTextW(hWnd, L"Argus Scanner - Not Attached");
            EnableWindow(g_hStartBtn, FALSE); EnableWindow(g_hShowMapBtn, FALSE);
            EnableWindow(g_hThreadsBtn, FALSE); EnableWindow(g_hIatHooksBtn, FALSE); EnableWindow(g_hSaveBtn, FALSE);
        }
        g_scanner.clear();
        ClearListViewItems(g_hListView);
        break;
    }
    case WM_APP_ADD_ITEM: {
        RwxScanner::ScanResult* result = (RwxScanner::ScanResult*)lParam;
        if (result) {
            LVITEMW lvi = { 0 }; lvi.mask = LVIF_TEXT | LVIF_PARAM; lvi.lParam = (LPARAM)result; lvi.iItem = ListView_GetItemCount(g_hListView);
            wchar_t buffer[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, result->timestamp, -1, buffer, MAX_PATH); lvi.iSubItem = 0; lvi.pszText = buffer;
            int itemIndex = ListView_InsertItem(g_hListView, &lvi);
            MultiByteToWideChar(CP_ACP, 0, result->status, -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 1, buffer);
            MultiByteToWideChar(CP_ACP, 0, result->region, -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 2, buffer);
            MultiByteToWideChar(CP_ACP, 0, result->size, -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 3, buffer);
            MultiByteToWideChar(CP_ACP, 0, result->protection, -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 4, buffer);
            MultiByteToWideChar(CP_ACP, 0, result->module, -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 5, buffer);
            MultiByteToWideChar(CP_UTF8, 0, result->heuristic_results.c_str(), -1, buffer, MAX_PATH); ListView_SetItemText(g_hListView, itemIndex, 6, buffer);
        }
        break;
    }
    case WM_SIZE: {
        int width = LOWORD(lParam); int height = HIWORD(lParam);
        MoveWindow(g_hListView, 10, 50, width - 20, height - 70, TRUE);
        break;
    }
    case WM_CLOSE: {
        DestroyWindow(hWnd);
        break;
    }
    case WM_DESTROY: {
        if (g_bIsScanning) { g_bIsScanning = false; if (g_hScanThread != NULL) { WaitForSingleObject(g_hScanThread, 2000); CloseHandle(g_hScanThread); } }
        if (g_hTargetProcess) { CloseHandle(g_hTargetProcess); }
        ClearListViewItems(g_hListView);
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}