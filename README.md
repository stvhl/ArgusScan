# ArgusScan
**Memory Analysis Tool for Windows**
---

## 📖 About The Project

**ArgusScan** is a tool for in-depth analysis of running Windows processes, designed to detect suspicious memory regions and uncover common API hooking techniques.

The tool attaches to a live process and periodically scans for memory regions with `Read-Write-Execute` (RWX) permissions, monitors changes in memory content and protection flags, and reports them to the user. It also includes modules for detecting techniques like process hollowing, thread injection, and IAT hooking.

---

## 🚀 Features

*   **Dynamic Memory Scanning**: Periodically scans the memory of a running process to list regions with `Execute` permissions (`RWX`, `RX`, etc.).
*   **Change Detection**: Instantly detects and highlights newly allocated or modified memory regions, tracking changes in both content and protection flags.
*   **IAT Hook Scanning**: Scans the Import Address Table (IAT) of a process to detect hooks and compares them against the original API addresses, attempting to identify the hooking module.
*   **Thread Analysis**: Lists all threads within the process and checks if their start addresses lie outside of a known module, exposing potentially suspicious threads.
*   **Detailed Memory Inspection**:
    *   **Disassembler**: Utilizes the [Capstone Engine](https://www.capstone-engine.org/) to disassemble memory regions.
    *   **Hexdump Viewer**: Inspects raw memory content in both hexadecimal and ASCII formats.
*   **Process Memory Map**: Displays the full memory map of the target process (committed, reserved, free) with detailed region information (type, protection, associated module).
*   **Session Management**: Save and load scan results to a file for later analysis.
