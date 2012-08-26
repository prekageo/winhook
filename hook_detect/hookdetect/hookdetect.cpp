#define DBGHELP_TRANSLATE_TCHAR

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>

#include "common.h"

void ErrorExit(LPTSTR lpszFunction) {
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    //LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL );

    // Display the error message and exit the process

    //lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    //_snwprintf_s((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), _TRUNCATE, TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
    //MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
    printf("%S failed with error %d: %S", lpszFunction, dw, lpMsgBuf);

    LocalFree(lpMsgBuf);
    //LocalFree(lpDisplayBuf);
}

// --------------------------------------------------------------------------------------
// service load and unload functions
// --------------------------------------------------------------------------------------

static SC_HANDLE schService;

int load_service(LPCTSTR service_name, LPCTSTR file_name) {
    SC_HANDLE schSCManager;

    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        ErrorExit(L"OpenSCManager");
        return 0;
    }

    schService = OpenService(schSCManager, service_name, DELETE | SERVICE_STOP);
    if (schService == NULL && GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        ErrorExit(L"OpenService");
        return 0;
    }

    if (schService != NULL) {
        SERVICE_STATUS serviceStatus;
        if (!ControlService(schService,SERVICE_CONTROL_STOP,&serviceStatus) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            ErrorExit(L"ControlService");
            return 0;
        }

        if (!DeleteService(schService)) {
            ErrorExit(L"DeleteService");
            return 0;
        }
        CloseServiceHandle(schService);
        Sleep(1000);
    }

    wchar_t path[MAX_PATH];
    if (!GetCurrentDirectory(MAX_PATH, path)) {
        ErrorExit(L"GetCurrentDirectory");
        return 0;
    }

    wcscat_s(path, MAX_PATH, L"\\");
    wcscat_s(path, MAX_PATH, file_name);

    schService = CreateService(schSCManager, service_name, service_name, SERVICE_START | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
    CloseServiceHandle(schSCManager);
    if (schService == NULL) {
        ErrorExit(L"CreateService");
        return 0;
    }

    BOOL status = StartService(schService, 0, 0);
    if (!status && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        ErrorExit(L"StartService");
        return 0;
    }
    return 1;
}

int unload_service() {
    SERVICE_STATUS serviceStatus;
    BOOL status;

    status = ControlService(schService,SERVICE_CONTROL_STOP,&serviceStatus);
    CloseServiceHandle(schService);
    return status;
}

// --------------------------------------------------------------------------------------
// symbol functions
// --------------------------------------------------------------------------------------

typedef DWORD (__stdcall *SymSetOptions_ptr)(__in DWORD SymOptions);
typedef BOOL (__stdcall *SymInitializeW_ptr)(__in HANDLE hProcess, __in_opt PCWSTR UserSearchPath, __in BOOL fInvadeProcess);
typedef DWORD64 (__stdcall *SymLoadModuleExW_ptr)(__in HANDLE hProcess, __in_opt HANDLE hFile, __in_opt PCWSTR ImageName, __in_opt PCWSTR ModuleName, __in DWORD64 BaseOfDll, __in DWORD DllSize, __in_opt PMODLOAD_DATA Data, __in_opt DWORD Flags);
typedef BOOL (__stdcall *SymFromNameW_ptr)(__in HANDLE hProcess, __in PCWSTR Name, __inout PSYMBOL_INFOW Symbol);
typedef BOOL (__stdcall *SymGetSearchPathW_ptr)(__in HANDLE hProcess, __out_ecount(SearchPathLength) PWSTR SearchPath, __in DWORD SearchPathLength);
typedef BOOL (__stdcall *SymSetSearchPathW_ptr)(__in HANDLE hProcess, __in_opt PCWSTR SearchPath);

static SymSetOptions_ptr     SymSetOptions_d;
static SymInitializeW_ptr    SymInitializeW_d;
static SymLoadModuleExW_ptr  SymLoadModuleExW_d;
static SymFromNameW_ptr      SymFromNameW_d;
static SymGetSearchPathW_ptr SymGetSearchPathW_d;
static SymSetSearchPathW_ptr SymSetSearchPathW_d;

static bool symbols_enabled = false;

int symbols_init() {
    HMODULE hmod = LoadLibrary(L"dbghelp.dll");
    if (!hmod) {
        ErrorExit(L"LoadLibrary");
        goto error;
    }

    SymSetOptions_d     = reinterpret_cast<SymSetOptions_ptr>    (GetProcAddress(hmod, "SymSetOptions"    ));
    SymInitializeW_d    = reinterpret_cast<SymInitializeW_ptr>   (GetProcAddress(hmod, "SymInitializeW"   ));
    SymLoadModuleExW_d  = reinterpret_cast<SymLoadModuleExW_ptr> (GetProcAddress(hmod, "SymLoadModuleExW" ));
    SymFromNameW_d      = reinterpret_cast<SymFromNameW_ptr>     (GetProcAddress(hmod, "SymFromNameW"     ));
    SymGetSearchPathW_d = reinterpret_cast<SymGetSearchPathW_ptr>(GetProcAddress(hmod, "SymGetSearchPathW"));
    SymSetSearchPathW_d = reinterpret_cast<SymSetSearchPathW_ptr>(GetProcAddress(hmod, "SymSetSearchPathW"));

    if (!SymSetOptions_d) {
        ErrorExit(L"GetProcAddress(SymSetOptions)");
        goto error;
    }

    if (!SymInitializeW_d) {
        ErrorExit(L"GetProcAddress(SymInitializeW)");
        goto error;
    }

    if (!SymLoadModuleExW_d) {
        ErrorExit(L"GetProcAddress(SymLoadModuleExW)");
        goto error;
    }

    if (!SymFromNameW_d) {
        ErrorExit(L"GetProcAddress(SymFromNameW)");
        goto error;
    }

    if (!SymGetSearchPathW_d) {
        ErrorExit(L"GetProcAddress(SymGetSearchPathW)");
        goto error;
    }

    if (!SymSetSearchPathW_d) {
        ErrorExit(L"GetProcAddress(SymSetSearchPathW)");
        goto error;
    }

    (*SymSetOptions_d)(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

    HANDLE hprocess = GetCurrentProcess();
    if (!(*SymInitializeW_d)(hprocess, NULL, FALSE)) {
        ErrorExit(L"SymInitialize");
        goto error;
    }

    wchar_t search_path[MAX_PATH];
    if (!(*SymGetSearchPathW_d)(hprocess, search_path, MAX_PATH)) {
        ErrorExit(L"SymGetSearchPath");
        goto error;
    }

    if (wcslen(search_path) <= 1) {
        if (!(*SymSetSearchPathW_d)(hprocess, L"srv*symbols*http://msdl.microsoft.com/download/symbols")) {
            ErrorExit(L"SymSetSearchPath");
            goto error;
        }
    }

    wchar_t path[MAX_PATH];
    if (!GetSystemDirectory(path, MAX_PATH)) {
        ErrorExit(L"GetSystemDirectory");
        goto error;
    }

    wcscat_s(path, MAX_PATH, L"\\win32k.sys");

    if (!(*SymLoadModuleExW_d)(hprocess, NULL, path, NULL, 0, 0, NULL, 0)) {
        ErrorExit(L"SymLoadModuleEx");
        goto error;
    }

    symbols_enabled = true;
    return 1;

error:
    return 0;
}

DWORD symbols_get_address_by_name(wchar_t *name) {
    if (!symbols_enabled) {
        return 0;
    }

    wchar_t szSymbolName[MAX_SYM_NAME];
    char buffer[sizeof(SYMBOL_INFO) + sizeof(szSymbolName)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    wcscpy_s(szSymbolName, MAX_SYM_NAME, name);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    if (!(*SymFromNameW_d)(GetCurrentProcess(), szSymbolName, pSymbol)) {
        ErrorExit(L"SymFromName");
        return 0;
    }

    return (DWORD)pSymbol->Address;
}

// --------------------------------------------------------------------------------------
// core hook monitor functions
// --------------------------------------------------------------------------------------

static HANDLE hDriverFile;
static PARAMS_GET_HOOKS params={0};

int hookmon_init() {
    if (!load_service(L"hookdetect",L"hookdetect.sys")) {
        return 0;
    }

    hDriverFile = CreateFile(L"\\\\.\\hookdetect",GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
    if (hDriverFile == 0) {
        ErrorExit(L"CreateFile");
        return 0;
    }

    if (!symbols_init()) {
        fprintf(stderr, "Warning: For module name resolution, put dbghelp.dll and symsrv.dll in the working directory.\n");
    }

    return 1;
}

struct THREAD {
    DWORD thread_id;
    DWORD process_id;
} threads[MAX_IN_THREADS];

#define MAX_PROCESSES 64

struct PROCESS {
    DWORD process_id;
    wchar_t exe_path[MAX_PATH];
} processes[MAX_PROCESSES];
int processes_count;

int thread_walk(DWORD *thread_ids, DWORD max_threads, unsigned int *thread_count) {
    HANDLE hThreadSnap;
    THREADENTRY32 te32;

    *thread_count = 0;

    // Take a snapshot of all running threads
    hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD | TH32CS_SNAPPROCESS, 0 );
    if( hThreadSnap == INVALID_HANDLE_VALUE ) {
        ErrorExit(L"CreateToolhelp32Snapshot");
        return( FALSE );
    }

    // Fill in the size of the structure before using it.
    te32.dwSize = sizeof(THREADENTRY32 );

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if( !Thread32First( hThreadSnap, &te32 ) ) {
        ErrorExit(L"Thread32First");
        CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
        return( FALSE );
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    unsigned int i = 0;
    do {
        if (i<max_threads) {
            thread_ids[i] = te32.th32ThreadID;
            threads[i].thread_id = te32.th32ThreadID;
            threads[i].process_id = te32.th32OwnerProcessID;
        }
        i++;
    } while( Thread32Next(hThreadSnap, &te32 ) );
    *thread_count = i;

    PROCESSENTRY32 pe32;
    MODULEENTRY32 me32;
    HANDLE hModuleSnap;

    pe32.dwSize = sizeof(pe32);
    me32.dwSize = sizeof(me32);
    if( !Process32First( hThreadSnap, &pe32 ) ) {
        ErrorExit(L"Process32First");
        CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
        return( FALSE );
    }

    i = 0;
    do {
        hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe32.th32ProcessID );
        if( hModuleSnap == INVALID_HANDLE_VALUE && GetLastError() != ERROR_ACCESS_DENIED ) {
            ErrorExit(L"CreateToolhelp32Snapshot");
            return( FALSE );
        }

        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            if (!Module32First(hModuleSnap, &me32)) {
                ErrorExit(L"Module32First");
                CloseHandle( hModuleSnap );     // Must clean up the snapshot object!
                return( FALSE );
            };
        }

        if (i<MAX_PROCESSES) {
            processes[i].process_id = pe32.th32ProcessID;
            if (hModuleSnap != INVALID_HANDLE_VALUE) {
                wcscpy_s(processes[i].exe_path, MAX_PATH, me32.szExePath);
            } else {
                wcscpy_s(processes[i].exe_path, MAX_PATH, pe32.szExeFile);
            }
        }
        i++;

        CloseHandle(hModuleSnap);
    } while (Process32Next(hThreadSnap, &pe32));
    processes_count = i;

    if (processes_count > MAX_PROCESSES) {
        fprintf(stderr, "Warning: %d processes running. Can handle only %d.\n", processes_count, MAX_PROCESSES);
    }

    //  Don't forget to clean up the snapshot object.
    CloseHandle( hThreadSnap );
    return( TRUE );
}

int hookmon_module_name_from_hmod_table_index(int hmod_table_index, wchar_t *module_name) {
    wcscpy_s(module_name, MAX_PATH, L"unavailable");

    PARAMS_HMOD_TBL_INX_TO_MOD_NAME params;
    params.UserGetAtomName_address = symbols_get_address_by_name(L"UserGetAtomName");
    params.aatomSysLoaded_address = symbols_get_address_by_name(L"aatomSysLoaded");
    params.hmod_table_index = hmod_table_index;

    DATA_HMOD_TBL_INX_TO_MOD_NAME data={0};
    DWORD bytes_ret;
    BOOL status = DeviceIoControl(hDriverFile,IOCTL_HMOD_TBL_INX_TO_MOD_NAME,&params,sizeof(params),&data,sizeof(data),&bytes_ret,NULL);
    if (status == 0) {
        ErrorExit(L"DeviceIoControl");
        return 0;
    }

    if (data.module_name[0]) {
        wcscpy_s(module_name, MAX_PATH, data.module_name);
    }

    return 1;
}


static char* hook_name[] = {"WH_MSGFILTER","WH_JOURNALRECORD","WH_JOURNALPLAYBACK","WH_KEYBOARD",
    "WH_GETMESSAGE","WH_CALLWNDPROC","WH_CBT","WH_SYSMSGFILTER","WH_MOUSE",
    "WH_HARDWARE","WH_DEBUG","WH_SHELL","WH_FOREGROUNDIDLE","WH_CALLWNDPROCRET",
    "WH_KEYBOARD_LL","WH_MOUSE_LL"};

void hookmon_dump_hooks(hook *hooks) {
    bool has_hooks = FALSE;
    for (int j=WH_MINHOOK;j<=WH_MAXHOOK;j++) {
        int i = HOOKID_TO_INDEX(j);
        if (hooks[i].handlers == 0)
            continue;
        has_hooks = TRUE;
        printf("  Hook: %s Count: %d\n", hook_name[i], hooks[i].handlers);
        if (hooks[i].handlers > MAX_HANDLERS) {
            fprintf(stderr, "Warning: %d handlers installed. Displaying only %d.\n", hooks[i].handlers, MAX_HANDLERS);
        }
        for (unsigned int j=0;j<min(MAX_HANDLERS,hooks[i].handlers);j++) {
            if (hooks[i].handler[j].hmod_table_index >= 0) {
                wchar_t module_name[MAX_PATH];
                hookmon_module_name_from_hmod_table_index(hooks[i].handler[j].hmod_table_index, module_name);
                printf("     Module: \"%S\" Relative address: 0x%08x\n",
                    module_name,
                    hooks[i].handler[j].proc_relative_offset
                    );
            } else {
                printf("    Address: 0x%08x\n", hooks[i].handler[j].proc_relative_offset);
            }
        }
    }
    if (!has_hooks) {
        printf("  No hooks.\n");
    }
    printf("\n");
}

int hookmon_dump() {
    unsigned int thread_count;
    if (!thread_walk(params.thread_id, MAX_IN_THREADS, &thread_count)) {
        fprintf(stderr, "Warning: Thread hooks won't be available.\n");
    }
    if (thread_count > MAX_IN_THREADS) {
        fprintf(stderr, "Warning: %d threads running. Will inspect only %d.\n", thread_count, MAX_IN_THREADS);
    }
    params.threads = min(thread_count, MAX_IN_THREADS);

    DATA_GET_HOOKS data={0};
    DWORD bytes_ret;
    BOOL status = DeviceIoControl(hDriverFile,IOCTL_GET_HOOKS,&params,sizeof(params),&data,sizeof(data),&bytes_ret,NULL);
    if (status == 0) {
        ErrorExit(L"DeviceIoControl");
        return 0;
    }

    printf("Global hooks:\n");
    hookmon_dump_hooks(data.global_hook);
    if (data.threads > MAX_OUT_THREADS) {
        fprintf(stderr, "Warning: %d threads have hooks. Displaying only %d.\n", data.threads, MAX_OUT_THREADS);
    }
    for (unsigned int i=0;i<min(MAX_OUT_THREADS,data.threads);i++) {
        DWORD pid=0;
        for (unsigned int j=0;j<params.threads;j++) {
            if (threads[j].thread_id == data.thread[i].thread_id) {
                pid = threads[j].process_id;
                break;
            }
        }
        wchar_t *process_exe_path = L"not found";
        for (int j=0;j<min(MAX_PROCESSES, processes_count);j++) {
            if (processes[j].process_id == pid) {
                process_exe_path = processes[j].exe_path;
                break;
            }
        }
        printf("Process path: \"%S\" Thread ID: %d\n", process_exe_path, data.thread[i].thread_id);
        hookmon_dump_hooks(data.thread[i].hook);
    }

    return 1;
}

void hookmon_cleanup() {
    unload_service();
}

int main() {
    fprintf(stderr, "\n");
    fprintf(stderr, "HookDetect - Windows hook viewer\n");
    fprintf(stderr, "George Prekas\n");
    fprintf(stderr, "\n");

    HWND hwnd = CreateWindow(L"STATIC", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!hwnd) {
        ErrorExit(L"CreateWindow");
        return 1;
    }

    if (!hookmon_init()) {
        return 1;
    }

    hookmon_dump();
    hookmon_cleanup();

    return 0;
}
