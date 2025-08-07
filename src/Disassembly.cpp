#include "Disassembly.h"
#include "WindowProcedures.h"
#include "Globals.h"

struct DisassembledInstruction {
    cs_insn* instruction;
};

struct DisasmWindowData {
    DisassemblyParams* params;
    std::vector<DisassembledInstruction> instructions;
    bool isHexdumpView;
    int lastClickedLine;
    csh capstoneHandle;
};

void PopulateDisassemblyView(HWND hWnd, HWND hRichEdit) {
    DisasmWindowData* data = (DisasmWindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (!data) return;

    std::wstringstream ss;
    ss << L"Address\t\tBytes\t\t\tMnemonic & Operands\r\n";
    ss << L"------------------------------------------------------------------------------------------------\r\n";

    for (const auto& disasm : data->instructions) {
        cs_insn* insn = disasm.instruction;
        ss << L"0x" << std::hex << insn->address << L"\t";
        for (size_t j = 0; j < insn->size; j++) {
            ss << std::setw(2) << std::setfill(L'0') << (int)insn->bytes[j] << L" ";
        }
        for (size_t j = insn->size; j < 12; ++j) ss << L"   ";

        wchar_t mnemonic_w[32], op_str_w[160];
        MultiByteToWideChar(CP_UTF8, 0, insn->mnemonic, -1, mnemonic_w, 32);
        MultiByteToWideChar(CP_UTF8, 0, insn->op_str, -1, op_str_w, 160);
        ss << mnemonic_w << L"\t" << op_str_w << L"\r\n";
    }

    SetWindowTextW(hRichEdit, ss.str().c_str());
    data->isHexdumpView = false;
}

void PopulateHexdumpView(HWND hWnd, HWND hRichEdit) {
    DisasmWindowData* data = (DisasmWindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (!data) return;

    std::wstringstream ss;
    const int bytes_per_line = 16;
    const std::vector<BYTE>& memoryBuffer = data->params->memoryBuffer;

    for (size_t i = 0; i < memoryBuffer.size(); i += bytes_per_line) {
        ss << L"0x" << std::hex << std::setfill(L'0') << std::setw(8) << (data->params->baseAddress + i) << L"  ";
        for (int j = 0; j < bytes_per_line; ++j) {
            if (i + j < memoryBuffer.size()) ss << std::setw(2) << (int)memoryBuffer[i + j] << L" ";
            else ss << L"   ";
            if (j == 7) ss << L" ";
        }
        ss << L" ";
        for (int j = 0; j < bytes_per_line; ++j) {
            if (i + j < memoryBuffer.size()) {
                wchar_t c = memoryBuffer[i + j];
                ss << (iswprint(c) ? c : L'.');
            }
        }
        ss << L"\r\n";
    }

    SetWindowTextW(hRichEdit, ss.str().c_str());
    data->isHexdumpView = true;
}

void PerformStackTrace(HWND hOwner, HANDLE hProcess, uintptr_t threadId, uintptr_t instructionPointer, uintptr_t stackPointer) {
    SymInitialize(hProcess, NULL, TRUE);
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = instructionPointer;
    context.Rsp = stackPointer;
    STACKFRAME64 stackFrame = {};
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context.Rsp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    std::wstringstream ss;
    ss << L"Stack Trace (from 0x" << std::hex << instructionPointer << L"):\r\n";
    ss << L"---------------------------------------\r\n";
    ss << L"NOTE: RSP is unknown and simulated. Trace may be inaccurate.\r\n\r\n";

    for (int i = 0; i < 50; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, (HANDLE)threadId, &stackFrame, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
        ss << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << stackFrame.AddrPC.Offset;
        DWORD64 displacement = 0;
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        if (SymFromAddr(hProcess, stackFrame.AddrPC.Offset, &displacement, pSymbol)) {
            ss << L" (" << pSymbol->Name << L" + 0x" << std::hex << displacement << L")\r\n";
        }
        else {
            ss << L" (symbols not found)\r\n";
        }
    }
    MessageBoxW(hOwner, ss.str().c_str(), L"Stack Trace", MB_OK);
    SymCleanup(hProcess);
}

LRESULT CALLBACK DisasmWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hRichEdit, hSearchBox, hSearchBtn;
    switch (msg) {
    case WM_CREATE: {
        LPCREATESTRUCT pCreate = (LPCREATESTRUCT)lParam;
        DisasmWindowData* data = new DisasmWindowData();
        data->params = (DisassemblyParams*)pCreate->lpCreateParams;
        data->isHexdumpView = false;
        data->lastClickedLine = -1;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)data);

        wchar_t windowTitle[100];
        swprintf_s(windowTitle, L"Disassembly of 0x%llX", data->params->baseAddress);
        SetWindowTextW(hWnd, windowTitle);

        hSearchBox = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 10, 5, 200, 25, hWnd, (HMENU)ID_EDIT_SEARCH, pCreate->hInstance, NULL);
        hSearchBtn = CreateWindowW(L"BUTTON", L"Search", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 220, 5, 150, 25, hWnd, (HMENU)ID_BTN_SEARCH, pCreate->hInstance, NULL);
        hRichEdit = CreateWindowExW(0, MSFTEDIT_CLASS, L"Disassembling, please wait...", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY, 10, 35, 660, 450, hWnd, (HMENU)ID_RICHEDIT_DISASM, pCreate->hInstance, NULL);
        SendMessage(hRichEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &data->capstoneHandle) != CS_ERR_OK) {
            SetWindowTextW(hRichEdit, L"ERROR: Failed to initialize Capstone engine!");
            break;
        }

        const auto& memBuffer = data->params->memoryBuffer;
        cs_insn* insn;
        size_t count = cs_disasm(data->capstoneHandle, memBuffer.data(), memBuffer.size(), data->params->baseAddress, 0, &insn);
        if (count > 0) {
            data->instructions.reserve(count);
            for (size_t i = 0; i < count; i++) {
                data->instructions.push_back({ &insn[i] });
            }
        }
        else {
            SetWindowTextW(hRichEdit, L"Failed to disassemble. Memory might not contain valid instructions.");
        }
        PopulateDisassemblyView(hWnd, hRichEdit);
        break;
    }
    case WM_CONTEXTMENU: {
        if ((HWND)wParam == hRichEdit) {
            DisasmWindowData* data = (DisasmWindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            if (!data) break;

            POINT pt = { LOWORD(lParam), HIWORD(lParam) };
            LRESULT charIndex = SendMessage(hRichEdit, EM_CHARFROMPOS, 0, (LPARAM)&pt);
            int lineIndex = SendMessage(hRichEdit, EM_LINEFROMCHAR, charIndex, 0);
            data->lastClickedLine = lineIndex;

            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_DISASM_COPY_LINE, L"Copy Line");
            AppendMenuW(hMenu, MF_STRING, IDM_DISASM_DUMP_TO_FILE, L"Dump Region to File");

            int instructionIndex = lineIndex - 2;
            if (!data->isHexdumpView && instructionIndex >= 0 && instructionIndex < data->instructions.size()) {
                cs_insn* insn = data->instructions[instructionIndex].instruction;
                if (strcmp(insn->mnemonic, "jmp") == 0 || strcmp(insn->mnemonic, "call") == 0) {
                    AppendMenuW(hMenu, MF_STRING, IDM_DISASM_GOTO_TARGET, L"Go to Target");
                }
                AppendMenuW(hMenu, MF_STRING, IDM_DISASM_STACK_TRACE, L"Simulate Stack Trace");
            }
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, IDM_DISASM_FIND_STRINGS, L"Find Strings in Region...");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            if (data->isHexdumpView) AppendMenuW(hMenu, MF_STRING, IDM_DISASM_VIEW_ASSEMBLY, L"View as Disassembly");
            else AppendMenuW(hMenu, MF_STRING, IDM_DISASM_VIEW_HEXDUMP, L"View as Hexdump");

            ClientToScreen(hRichEdit, &pt);
            TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
        break;
    }
    case WM_COMMAND: {
        DisasmWindowData* data = (DisasmWindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!data) break;
        switch (LOWORD(wParam)) {
        case ID_BTN_SEARCH: {
            wchar_t searchTerm[256];
            GetWindowTextW(hSearchBox, searchTerm, 256);
            if (wcslen(searchTerm) == 0) break;
            CHARFORMAT2W cf_clear = {}; cf_clear.cbSize = sizeof(cf_clear); cf_clear.dwMask = CFM_BACKCOLOR; cf_clear.crBackColor = GetSysColor(COLOR_WINDOW);
            SendMessage(hRichEdit, EM_SETSEL, 0, -1);
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf_clear);
            CHARFORMAT2W cf_highlight = {}; cf_highlight.cbSize = sizeof(cf_highlight); cf_highlight.dwMask = CFM_BACKCOLOR; cf_highlight.crBackColor = RGB(255, 255, 0);
            FINDTEXTEXW ft = {}; ft.chrg.cpMin = 0; ft.chrg.cpMax = -1; ft.lpstrText = searchTerm;
            long findResult = 0; int matchCount = 0;
            while (findResult >= 0) {
                findResult = SendMessageW(hRichEdit, EM_FINDTEXTEXW, FR_DOWN | FR_MATCHCASE, (LPARAM)&ft);
                if (findResult != -1) {
                    matchCount++;
                    SendMessageW(hRichEdit, EM_SETSEL, ft.chrgText.cpMin, ft.chrgText.cpMax);
                    SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf_highlight);
                    ft.chrg.cpMin = ft.chrgText.cpMax;
                }
                else break;
            }
            SendMessage(hRichEdit, EM_SETSEL, 0, 0);
            if (matchCount == 0) MessageBoxW(hWnd, L"Text not found.", L"Search Result", MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDM_DISASM_COPY_LINE: {
            if (data->lastClickedLine >= 0) {
                wchar_t lineBuffer[512];
                *(WORD*)lineBuffer = 512;
                int len = SendMessage(hRichEdit, EM_GETLINE, data->lastClickedLine, (LPARAM)lineBuffer);
                lineBuffer[len] = L'\0';
                if (OpenClipboard(hWnd)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (wcslen(lineBuffer) + 1) * sizeof(wchar_t));
                    if (hg) { memcpy(GlobalLock(hg), lineBuffer, (wcslen(lineBuffer) + 1) * sizeof(wchar_t)); GlobalUnlock(hg); SetClipboardData(CF_UNICODETEXT, hg); }
                    CloseClipboard();
                }
            }
            break;
        }
        case IDM_DISASM_DUMP_TO_FILE: {
            std::wstringstream ss_filename;
            ss_filename << L"dump_0x" << std::hex << data->params->baseAddress;
            std::wstring base_filename = ss_filename.str();
            std::ofstream f_bin((base_filename + L".bin").c_str(), std::ios::binary);
            f_bin.write((char*)data->params->memoryBuffer.data(), data->params->memoryBuffer.size());
            f_bin.close();
            std::wofstream f_asm((base_filename + L".asm").c_str());
            wchar_t current_text[1024];
            int line_count = SendMessage(hRichEdit, EM_GETLINECOUNT, 0, 0);
            for (int i = 0; i < line_count; i++) {
                *(WORD*)current_text = 1024;
                int len = SendMessage(hRichEdit, EM_GETLINE, i, (LPARAM)current_text);
                current_text[len] = L'\0';
                f_asm << current_text << L"\r\n";
            }
            f_asm.close();
            MessageBoxW(hWnd, (L"Region dumped to " + base_filename + L".bin and .asm").c_str(), L"Dump Complete", MB_OK);
            break;
        }
        case IDM_DISASM_STACK_TRACE: {
            int instructionIndex = data->lastClickedLine - 2;
            if (!data->isHexdumpView && instructionIndex >= 0 && instructionIndex < data->instructions.size()) {
                cs_insn* insn = data->instructions[instructionIndex].instruction;
                PerformStackTrace(hWnd, data->params->hProcess, 0, insn->address, 0);
            }
            break;
        }
        case IDM_DISASM_FIND_STRINGS: {
            if (g_hStringsViewWnd && IsWindow(g_hStringsViewWnd)) { SetForegroundWindow(g_hStringsViewWnd); }
            else { g_hStringsViewWnd = CreateWindowExW(WS_EX_TOOLWINDOW, STRINGS_VIEW_CLASS_NAME, L"Strings View", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, hWnd, NULL, (HINSTANCE)GetWindowLongPtr(g_hMainWnd, GWLP_HINSTANCE), data->params); }
            break;
        }
        case IDM_DISASM_GOTO_TARGET: {
            int instructionIndex = data->lastClickedLine - 2;
            if (!data->isHexdumpView && instructionIndex >= 0 && instructionIndex < data->instructions.size()) {
                cs_insn* insn = data->instructions[instructionIndex].instruction;
                try {
                    uintptr_t targetAddress = std::stoull(std::string(insn->op_str), nullptr, 16);
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(data->params->hProcess, (LPCVOID)targetAddress, &mbi, sizeof(mbi))) {
                        DisassemblyParams* new_params = new DisassemblyParams();
                        new_params->baseAddress = (uintptr_t)mbi.BaseAddress;
                        new_params->regionSize = mbi.RegionSize;
                        new_params->hProcess = data->params->hProcess;
                        new_params->memoryBuffer.resize(mbi.RegionSize);
                        SIZE_T bytesRead;
                        ReadProcessMemory(new_params->hProcess, (LPCVOID)new_params->baseAddress, new_params->memoryBuffer.data(), new_params->regionSize, &bytesRead);
                        new_params->memoryBuffer.resize(bytesRead);
                        CreateWindowExW(WS_EX_TOOLWINDOW, DISASM_CLASS_NAME, L"Disassembly", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, g_hMainWnd, NULL, (HINSTANCE)GetWindowLongPtr(g_hMainWnd, GWLP_HINSTANCE), new_params);
                    }
                    else { MessageBoxW(hWnd, L"Could not query target address.", L"Error", MB_OK | MB_ICONERROR); }
                }
                catch (...) { MessageBoxW(hWnd, L"Could not parse target address from operand.", L"Error", MB_OK | MB_ICONERROR); }
            }
            break;
        }
        case IDM_DISASM_VIEW_HEXDUMP: { PopulateHexdumpView(hWnd, hRichEdit); break; }
        case IDM_DISASM_VIEW_ASSEMBLY: { PopulateDisassemblyView(hWnd, hRichEdit); break; }
        }
        break;
    }
    case WM_SIZE: {
        int width = LOWORD(lParam); int height = HIWORD(lParam);
        MoveWindow(hSearchBox, 10, 5, width - 200, 25, TRUE);
        MoveWindow(hSearchBtn, width - 180, 5, 170, 25, TRUE);
        MoveWindow(hRichEdit, 10, 35, width - 20, height - 50, TRUE);
        break;
    }
    case WM_CLOSE: DestroyWindow(hWnd); break;
    case WM_DESTROY: {
        DisasmWindowData* data = (DisasmWindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (data) {
            if (!data->instructions.empty()) cs_free(data->instructions[0].instruction, data->instructions.size());
            cs_close(&data->capstoneHandle);
            delete data->params;
            delete data;
        }
        g_hDisasmWnd = NULL;
        break;
    }
    default: return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}