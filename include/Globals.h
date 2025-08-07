#pragma once
#include "framework.h"
#include "RwxScanner.h"

extern HWND g_hMainWnd;
extern HWND g_hListView;
extern HWND g_hAttachBtn;
extern HWND g_hStartBtn;
extern HWND g_hStopBtn;
extern HWND g_hShowMapBtn;
extern HWND g_hSaveBtn;
extern HWND g_hLoadBtn;
extern HWND g_hThreadsBtn;
extern HWND g_hIatHooksBtn;

extern HANDLE g_hScanThread;
extern std::atomic<bool> g_bIsScanning;
extern RwxScanner g_scanner;
extern HANDLE g_hTargetProcess;
extern DWORD g_dwTargetPid;
extern wchar_t g_wszTargetProcessName[MAX_PATH];

extern HWND g_hDisasmWnd;
extern HWND g_hProcListWnd;
extern HWND g_hMemMapWnd;
extern HWND g_hThreadsWnd;
extern HWND g_hIatHookWnd;
extern HWND g_hStringsViewWnd;