#pragma once
#include "framework.h"

struct DisassemblyParams {
    uintptr_t baseAddress;
    size_t regionSize;
    HANDLE hProcess;
    std::vector<BYTE> memoryBuffer;
};
