#include "Globals.h"

HWND g_hMainWnd = NULL;
HWND g_hListView = NULL;
HWND g_hAttachBtn = NULL;
HWND g_hStartBtn = NULL;
HWND g_hStopBtn = NULL;
HWND g_hShowMapBtn = NULL;
HWND g_hSaveBtn = NULL;
HWND g_hLoadBtn = NULL;
HWND g_hThreadsBtn = NULL;
HWND g_hIatHooksBtn = NULL;

HANDLE g_hScanThread = NULL;
std::atomic<bool> g_bIsScanning = false;
RwxScanner g_scanner;
HANDLE g_hTargetProcess = NULL;
DWORD g_dwTargetPid = 0;
wchar_t g_wszTargetProcessName[MAX_PATH] = L"";

HWND g_hDisasmWnd = NULL;
HWND g_hProcListWnd = NULL;
HWND g_hMemMapWnd = NULL;
HWND g_hThreadsWnd = NULL;
HWND g_hIatHookWnd = NULL;
HWND g_hStringsViewWnd = NULL;