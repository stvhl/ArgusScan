#include "Disassembly.h"
#include "framework.h"
#include "Globals.h"
#include "WindowProcedures.h"

void RegisterWindowClasses(HINSTANCE hInstance) {
    WNDCLASSW wcMain = { 0 };
    wcMain.lpfnWndProc = WndProc;
    wcMain.hInstance = hInstance;
    wcMain.lpszClassName = MAIN_CLASS_NAME;
    wcMain.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcMain.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wcMain);

    WNDCLASSW wcDisasm = { 0 };
    wcDisasm.lpfnWndProc = DisasmWndProc;
    wcDisasm.hInstance = hInstance;
    wcDisasm.lpszClassName = DISASM_CLASS_NAME;
    wcDisasm.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcDisasm.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcDisasm.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wcDisasm);

    WNDCLASSW wcProcList = { 0 };
    wcProcList.lpfnWndProc = ProcListWndProc;
    wcProcList.hInstance = hInstance;
    wcProcList.lpszClassName = PROC_LIST_CLASS_NAME;
    wcProcList.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcProcList.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcProcList.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wcProcList);

    WNDCLASSW wcMemMap = { 0 };
    wcMemMap.lpfnWndProc = MemMapWndProc;
    wcMemMap.hInstance = hInstance;
    wcMemMap.lpszClassName = MEMORY_MAP_CLASS_NAME;
    wcMemMap.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcMemMap.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcMemMap.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wcMemMap);

    WNDCLASSW wcThreads = { 0 };
    wcThreads.lpfnWndProc = ThreadsWndProc;
    wcThreads.hInstance = hInstance;
    wcThreads.lpszClassName = THREADS_CLASS_NAME;
    wcThreads.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcThreads.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcThreads.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    RegisterClassW(&wcThreads);

    WNDCLASSW wcIat = { 0 };
    wcIat.lpfnWndProc = IatHookWndProc;
    wcIat.hInstance = hInstance;
    wcIat.lpszClassName = IAT_HOOK_CLASS_NAME;
    wcIat.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcIat.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcIat.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wcIat);

    WNDCLASSW wcStrings = { 0 };
    wcStrings.lpfnWndProc = StringsViewWndProc;
    wcStrings.hInstance = hInstance;
    wcStrings.lpszClassName = STRINGS_VIEW_CLASS_NAME;
    wcStrings.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcStrings.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcStrings.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wcStrings);
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    LoadLibrary(TEXT("Msftedit.dll"));
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    RegisterWindowClasses(hInstance);

    HWND hwnd = CreateWindowExW(0, MAIN_CLASS_NAME, L"Argus Scanner - Not Attached", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 980, 600, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) {
        return 0;
    }
    ShowWindow(hwnd, nCmdShow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        HWND hActiveDialog = NULL;
        if (g_hDisasmWnd && IsWindow(g_hDisasmWnd)) hActiveDialog = g_hDisasmWnd;
        else if (g_hProcListWnd && IsWindow(g_hProcListWnd)) hActiveDialog = g_hProcListWnd;
        else if (g_hMemMapWnd && IsWindow(g_hMemMapWnd)) hActiveDialog = g_hMemMapWnd;
        else if (g_hThreadsWnd && IsWindow(g_hThreadsWnd)) hActiveDialog = g_hThreadsWnd;
        else if (g_hIatHookWnd && IsWindow(g_hIatHookWnd)) hActiveDialog = g_hIatHookWnd;
        else if (g_hStringsViewWnd && IsWindow(g_hStringsViewWnd)) hActiveDialog = g_hStringsViewWnd;

        if (hActiveDialog == NULL || !IsDialogMessage(hActiveDialog, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}