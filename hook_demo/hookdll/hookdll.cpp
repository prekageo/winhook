#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>

#include "hookdll.h"

using namespace std;

static HMODULE hmod;
static vector<HHOOK> hooks;

BOOL WINAPI DllMain(__in HINSTANCE hinstDLL, __in DWORD fdwReason, __in LPVOID lpvReserved) {
    hmod = hinstDLL;
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

int process_walk(DWORD *pid) {
    HANDLE hThreadSnap;
    PROCESSENTRY32 te32;

    // Take a snapshot of all running threads
    hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if( hThreadSnap == INVALID_HANDLE_VALUE ) {
        return( FALSE );
    }

    // Fill in the size of the structure before using it.
    te32.dwSize = sizeof(PROCESSENTRY32 );

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if( !Process32First( hThreadSnap, &te32 ) ) {
        CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
        return( FALSE );
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do {
        if (wcsstr(te32.szExeFile, L"notepad.exe")) {
            *pid = te32.th32ProcessID;
            break;
        }
    } while( Process32Next(hThreadSnap, &te32 ) );

    //  Don't forget to clean up the snapshot object.
    CloseHandle( hThreadSnap );
    return( TRUE );
}

int thread_walk(DWORD pid, DWORD *tid) {
    HANDLE hThreadSnap;
    THREADENTRY32 te32;

    // Take a snapshot of all running threads
    hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if( hThreadSnap == INVALID_HANDLE_VALUE ) {
        return( FALSE );
    }

    // Fill in the size of the structure before using it.
    te32.dwSize = sizeof(THREADENTRY32 );

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if( !Thread32First( hThreadSnap, &te32 ) ) {
        CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
        return( FALSE );
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do {
        if (te32.th32OwnerProcessID==pid) {
            *tid = te32.th32ThreadID;
            break;
        }
    } while( Thread32Next(hThreadSnap, &te32 ) );

    //  Don't forget to clean up the snapshot object.
    CloseHandle( hThreadSnap );
    return( TRUE );
}

void log(char *msg, int code, int wparam, int lparam) {
    FILE *fd = fopen("c:\\hook_log.txt","a");
    fprintf(fd, msg, code, wparam, lparam);
    fclose(fd);
}

#define LOCAL_HOOK_PROC(v,x) \
LRESULT CALLBACK hook_proc_local_##x(__in int code, __in WPARAM wParam, __in LPARAM lParam) { \
    if (v) \
        log("local " #x "(%d,%d,%d) \n",code,wParam,lParam); \
    return CallNextHookEx(0, code, wParam, lParam); \
}

#define GLOBAL_HOOK_PROC(v,x) \
LRESULT CALLBACK hook_proc_global_##x(__in int code, __in WPARAM wParam, __in LPARAM lParam) { \
    if (v) \
        log("global " #x "(%d,%d,%d) \n",code,wParam,lParam); \
    return CallNextHookEx(0, code, wParam, lParam); \
}

#define SET_HOOK(y,x,tid) \
    hhook = SetWindowsHookEx(x, hook_proc_##y##_##x, hmod, tid); \
    if (hhook) \
        hooks.push_back(hhook); \
    else \
        printf(#y " " #x " set failed.\n");

#define SET_LOCAL_HOOK(x) \
    if (tid) {\
        SET_HOOK(local, ##x, tid) \
    }
#define SET_GLOBAL_HOOK(x) SET_HOOK(global, ##x, 0)
#define nET_GLOBAL_HOOK(x) do { } while (0)

LOCAL_HOOK_PROC(0,WH_MSGFILTER);       GLOBAL_HOOK_PROC(0,WH_MSGFILTER);
                                       GLOBAL_HOOK_PROC(1,WH_JOURNALRECORD);
                                       GLOBAL_HOOK_PROC(1,WH_JOURNALPLAYBACK);
LOCAL_HOOK_PROC(1,WH_KEYBOARD);        GLOBAL_HOOK_PROC(1,WH_KEYBOARD);
LOCAL_HOOK_PROC(0,WH_GETMESSAGE);      GLOBAL_HOOK_PROC(0,WH_GETMESSAGE);
LOCAL_HOOK_PROC(0,WH_CALLWNDPROC);     GLOBAL_HOOK_PROC(0,WH_CALLWNDPROC);
LOCAL_HOOK_PROC(0,WH_CBT);             GLOBAL_HOOK_PROC(0,WH_CBT);
                                       GLOBAL_HOOK_PROC(0,WH_SYSMSGFILTER);
LOCAL_HOOK_PROC(0,WH_MOUSE);           GLOBAL_HOOK_PROC(0,WH_MOUSE);
LOCAL_HOOK_PROC(1,8);                  GLOBAL_HOOK_PROC(1,8);
LOCAL_HOOK_PROC(0,WH_DEBUG);           GLOBAL_HOOK_PROC(0,WH_DEBUG);
LOCAL_HOOK_PROC(1,WH_SHELL);           GLOBAL_HOOK_PROC(1,WH_SHELL);
LOCAL_HOOK_PROC(0,WH_FOREGROUNDIDLE);  GLOBAL_HOOK_PROC(0,WH_FOREGROUNDIDLE);
LOCAL_HOOK_PROC(0,WH_CALLWNDPROCRET);  GLOBAL_HOOK_PROC(0,WH_CALLWNDPROCRET);
                                       GLOBAL_HOOK_PROC(1,WH_KEYBOARD_LL);
                                       GLOBAL_HOOK_PROC(1,WH_MOUSE_LL);

void hookdll_install() {
    DWORD pid=0, tid=0;
    process_walk(&pid);
    if (pid) {
        thread_walk(pid,&tid);
    }
    if (tid) {
        printf("Notepad's thread ID: %d\n", tid);
    } else {
        printf("Notepad is not running. Local hooks disabled.\n");
    }

    HHOOK hhook;

    SET_LOCAL_HOOK(WH_MSGFILTER);       SET_GLOBAL_HOOK(WH_MSGFILTER);
/* Disabled because they lock up the system.
                                        SET_GLOBAL_HOOK(WH_JOURNALRECORD);
                                        SET_GLOBAL_HOOK(WH_JOURNALPLAYBACK);
*/
    SET_LOCAL_HOOK(WH_KEYBOARD);        SET_GLOBAL_HOOK(WH_KEYBOARD);
    SET_LOCAL_HOOK(WH_GETMESSAGE);      SET_GLOBAL_HOOK(WH_GETMESSAGE);
    SET_LOCAL_HOOK(WH_CALLWNDPROC);     SET_GLOBAL_HOOK(WH_CALLWNDPROC);
    SET_LOCAL_HOOK(WH_CBT);             SET_GLOBAL_HOOK(WH_CBT);
                                        SET_GLOBAL_HOOK(WH_SYSMSGFILTER);
    SET_LOCAL_HOOK(WH_MOUSE);           SET_GLOBAL_HOOK(WH_MOUSE);
    SET_LOCAL_HOOK(8);                  SET_GLOBAL_HOOK(8);
    SET_LOCAL_HOOK(WH_DEBUG);           SET_GLOBAL_HOOK(WH_DEBUG);
    SET_LOCAL_HOOK(WH_SHELL);           SET_GLOBAL_HOOK(WH_SHELL);
    SET_LOCAL_HOOK(WH_FOREGROUNDIDLE);  SET_GLOBAL_HOOK(WH_FOREGROUNDIDLE);
    SET_LOCAL_HOOK(WH_CALLWNDPROCRET);  SET_GLOBAL_HOOK(WH_CALLWNDPROCRET);
/* Disabled for performance reasons.
                                        SET_GLOBAL_HOOK(WH_KEYBOARD_LL);
                                        SET_GLOBAL_HOOK(WH_MOUSE_LL);
*/
}

void hookdll_uninstall() {
    printf("Unhooking...\n");
    for (vector<HHOOK>::const_iterator hook = hooks.begin(); hook != hooks.end(); ++hook) {
        UnhookWindowsHookEx(*hook);
    }
}
