#include "WindowProcedures.h"
#include "Disassembly.h"
#include "Globals.h"

LRESULT CALLBACK StringsViewWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hRichEdit;
    switch (msg) {
    case WM_CREATE: {
        hRichEdit = CreateWindowExW(0, MSFTEDIT_CLASS, L"Searching...", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | ES_MULTILINE | ES_READONLY,
            0, 0, 0, 0, hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        SendMessage(hRichEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);

        DisassemblyParams* params = (DisassemblyParams*)((LPCREATESTRUCT)lParam)->lpCreateParams;
        if (!params) break;

        const std::vector<BYTE>& buffer = params->memoryBuffer;
        std::wstringstream ss;
        ss << L"Address      | String\r\n";
        ss << L"---------------------------------------\r\n\r\n";
        ss << L"--- ASCII Strings (min 5 chars) ---\r\n";

        std::string current_str;
        for (size_t i = 0; i < buffer.size(); ++i) {
            if (isprint(buffer[i])) {
                current_str += buffer[i];
            }
            else {
                if (current_str.length() >= 5) {
                    ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (params->baseAddress + i - current_str.length()) << L": " << std::wstring(current_str.begin(), current_str.end()) << L"\r\n";
                }
                current_str.clear();
            }
        }
        if (current_str.length() >= 5) {
            ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (params->baseAddress + buffer.size() - current_str.length()) << L": " << std::wstring(current_str.begin(), current_str.end()) << L"\r\n";
        }

        ss << L"\r\n--- Unicode Strings (min 5 chars) ---\r\n";
        std::wstring current_wstr;
        for (size_t i = 0; i + 1 < buffer.size(); i += 2) {
            wchar_t wc = *(wchar_t*)(&buffer[i]);
            if (iswprint(wc) && wc != L'\r' && wc != L'\n') {
                current_wstr += wc;
            }
            else {
                if (current_wstr.length() >= 5) {
                    ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (params->baseAddress + i - (current_wstr.length() * 2)) << L": " << current_wstr << L"\r\n";
                }
                current_wstr.clear();
            }
        }
        if (current_wstr.length() >= 5) {
            ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (params->baseAddress + buffer.size() - (current_wstr.length() * 2)) << L": " << current_wstr << L"\r\n";
        }

        SetWindowTextW(hRichEdit, ss.str().c_str());
        break;
    }
    case WM_SIZE: { RECT rcClient; GetClientRect(hWnd, &rcClient); MoveWindow(hRichEdit, 0, 0, rcClient.right, rcClient.bottom, TRUE); break; }
    case WM_CLOSE: DestroyWindow(hWnd); break;
    case WM_DESTROY: {
        g_hStringsViewWnd = NULL;
        break;
    }
    default: return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}