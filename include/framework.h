#pragma once

#include <sdkddkver.h>
#define _WIN32_WINNT 0x0600
#define _WIN32_IE 0x0700
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <psapi.h>
#include <richedit.h>
#include <DbgHelp.h>
#include <Shlwapi.h>
#include <TlHelp32.h>

#include <iostream>
#include <vector>
#include <set>
#include <unordered_map>
#include <string>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <atomic>

#include <capstone/capstone.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "capstone.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef LONG NTSTATUS;
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation, ThreadTimes, ThreadPriority, ThreadBasePriority,
    ThreadAffinityMask, ThreadImpersonationToken, ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup, ThreadEventPair, ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell, ThreadPerformanceCount, ThreadAmILastThread,
    ThreadIdealProcessor, ThreadPriorityBoost, ThreadSetTlsArrayAddress,
    ThreadIsIoPending, ThreadHideFromDebugger
} THREADINFOCLASS;

#define ID_BTN_ATTACH      100
#define ID_BTN_START       101
#define ID_BTN_STOP        102
#define ID_LIST_VIEW       103
#define ID_BTN_SHOW_MAP    104
#define ID_BTN_SAVE        105
#define ID_BTN_LOAD        106
#define ID_BTN_THREADS     107
#define ID_BTN_IAT_HOOKS   108

#define ID_PROC_LIST_VIEW  201
#define ID_BTN_PROC_OK     202
#define ID_BTN_PROC_CANCEL 203

#define ID_RICHEDIT_DISASM 500
#define ID_EDIT_SEARCH     501
#define ID_BTN_SEARCH      502

#define IDM_DISASM_FIRST         600
#define IDM_DISASM_COPY_LINE     (IDM_DISASM_FIRST + 1)
#define IDM_DISASM_GOTO_TARGET   (IDM_DISASM_FIRST + 2)
#define IDM_DISASM_VIEW_HEXDUMP  (IDM_DISASM_FIRST + 3)
#define IDM_DISASM_VIEW_ASSEMBLY (IDM_DISASM_FIRST + 4)
#define IDM_DISASM_DUMP_TO_FILE  (IDM_DISASM_FIRST + 5)
#define IDM_DISASM_STACK_TRACE   (IDM_DISASM_FIRST + 6)
#define IDM_DISASM_FIND_STRINGS  (IDM_DISASM_FIRST + 7)

#define WM_APP_ADD_ITEM (WM_APP + 1)
#define WM_APP_PROCESS_SELECTED (WM_APP + 2)

const wchar_t MAIN_CLASS_NAME[] = L"RwxScannerWindowClass";
const wchar_t DISASM_CLASS_NAME[] = L"DisassemblerWindowClass";
const wchar_t PROC_LIST_CLASS_NAME[] = L"ProcessListWindowClass";
const wchar_t MEMORY_MAP_CLASS_NAME[] = L"MemoryMapWindowClass";
const wchar_t THREADS_CLASS_NAME[] = L"ThreadsWindowClass";
const wchar_t IAT_HOOK_CLASS_NAME[] = L"IatHookWindowClass";
const wchar_t STRINGS_VIEW_CLASS_NAME[] = L"StringsViewWindowClass";