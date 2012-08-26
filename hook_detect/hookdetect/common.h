#define IOCTL_GET_HOOKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HMOD_TBL_INX_TO_MOD_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
//
#define WH_MIN    (-1)
//#define WH_MSGFILTER    (-1)
//#define WH_JOURNALRECORD    0
//#define WH_JOURNALPLAYBACK    1
//#define WH_KEYBOARD    2
//#define WH_GETMESSAGE    3
//#define WH_CALLWNDPROC    4
//#define WH_CBT    5
//#define WH_SYSMSGFILTER    6
//#define WH_MOUSE    7
//#define WH_HARDWARE    8
//#define WH_DEBUG    9
//#define WH_SHELL    10
//#define WH_FOREGROUNDIDLE    11
//#define WH_CALLWNDPROCRET    12
//#define WH_KEYBOARD_LL    13
//#define WH_MOUSE_LL    14
#define WH_MAX        14
#define WH_MINHOOK    WH_MIN
#define WH_MAXHOOK    WH_MAX
#define NB_HOOKS (WH_MAXHOOK-WH_MINHOOK+1)
#define HOOKID_TO_INDEX(HookId) (HookId - WH_MINHOOK)

#define MAX_HANDLERS 4
#define MAX_IN_THREADS 1024
#define MAX_OUT_THREADS 64

typedef struct {
    DWORD handlers;
    struct {
        struct {
            DWORD unknown_0;
            DWORD unknown_4;
            DWORD unknown_8;
            DWORD unknown_C;
            DWORD self_address;
            DWORD next_address;
            DWORD hook_type;
            DWORD flags;
            DWORD thread_id;
        } internal_stuff;
        int hmod_table_index;
        DWORD module_base;
        DWORD proc_relative_offset;
    } handler[MAX_HANDLERS];
} hook;

typedef struct {
    hook global_hook[NB_HOOKS];
    DWORD threads;
    struct {
        DWORD thread_id;
        hook hook[NB_HOOKS];
    } thread[MAX_OUT_THREADS];
} DATA_GET_HOOKS;

typedef struct {
    DWORD threads;
    DWORD thread_id[MAX_IN_THREADS];
} PARAMS_GET_HOOKS;

typedef struct {
    DWORD UserGetAtomName_address;
    DWORD aatomSysLoaded_address;
    int hmod_table_index;
} PARAMS_HMOD_TBL_INX_TO_MOD_NAME;

typedef struct {
    WCHAR module_name[MAX_PATH];
} DATA_HMOD_TBL_INX_TO_MOD_NAME;
