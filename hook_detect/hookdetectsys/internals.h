typedef int PEX_PUSH_LOCK;
typedef int PRTL_AVL_COMPARE_ROUTINE;
typedef int PRTL_AVL_ALLOCATE_ROUTINE;
typedef int PRTL_AVL_FREE_ROUTINE;
typedef int PCLIENTTHREADINFO;
typedef int PCLIENTINFO;
typedef int CLIENTTHREADINFO;
typedef int PCLS;
typedef int PWOWPROCESSINFO;
typedef int USERSTARTUPINFO;
typedef int W32HEAP_USER_MAPPING;
typedef int PQ;
typedef int PKL;
typedef int PDESKTOP;
typedef int PSMS;
typedef int PMENUSTATE;
typedef int PTDB;
typedef int PWINDOWSTATION;
typedef int PSVR_INSTANCE_INFO;
typedef int PMOVESIZEDATA;
typedef int PSBTRACK;
typedef int PWND;
typedef int PIMC;
typedef int MLIST;

#define CLIBS 32
#define CWINHOOKS 32

typedef struct tagHOOK* PHOOK;

typedef struct tagHOOK {
    DWORD unknown_0;
    DWORD unknown_4;
    DWORD unknown_8;
    DWORD unknown_C;
    PHOOK self_address;
    PHOOK next_address;
    DWORD hook_type;
    DWORD proc_relative_offset;
    DWORD flags;
    int hmod_table_index;
    DWORD thread_id;
} HOOK;

typedef struct _THREADINFO *PTHREADINFO;
typedef struct _PROCESSINFO *PPROCESSINFO;

typedef struct _DESKTOPINFO
{
    PVOID pvDesktopBase;
    PVOID pvDesktopLimit;
    struct _WND *spwnd;
    DWORD fsHooks;
    PHOOK aphkStart[NB_HOOKS];

    HWND hTaskManWindow;
    HWND hProgmanWindow;
    HWND hShellWindow;

    union
    {
        UINT Dummy;
        struct
        {
            UINT LastInputWasKbd : 1;
        };
    };

    WCHAR szDesktopName[1];
} DESKTOPINFO, *PDESKTOPINFO;

// FIXME! Move to ntuser.h
typedef struct _TL
{
    struct _TL* next;
    PVOID pobj;
    PVOID pfnFree;
} TL, *PTL;

typedef struct _W32THREAD
{
    PETHREAD pEThread;
    ULONG RefCount;
    PTL ptlW32;
    PVOID pgdiDcattr;
    PVOID pgdiBrushAttr;
    PVOID pUMPDObjs;
    PVOID pUMPDHeap;
    DWORD dwEngAcquireCount;
    PVOID pSemTable;
    PVOID pUMPDObj;
} W32THREAD, *PW32THREAD;

typedef struct _THREADINFO {
    W32THREAD;                  // W32THREAD
    PTL                    ptl;        // Listhead for thread lock list            +28
    PPROCESSINFO        ppi;        // process info struct for this thread        +2C
    PQ                    pq;         // keyboard and mouse input queue            +30
    PKL                    spklActive;    // active keyboard layout for this thread    +34
    PCLIENTTHREADINFO    pcti;       // Info that must be visible from client    +38
    PDESKTOP            rpdesk;
    PDESKTOPINFO        pDeskInfo;  // Desktop info visible to client            +40
    PCLIENTINFO            pClientInfo;// Client info stored in TEB                +44
    ULONG               TIF_flags;  // TIF_ flags go here.                        +48
    PUNICODE_STRING     pstrAppName;// Application module name.                    +4C
    PSMS                psmsSent;    // Most recent SMS this thread has sent
    PSMS                psmsCurrent;    // Received SMS this thread is currently processing
    PSMS                psmsReceiveList;// SMSs to be processed
    LONG                timeLast;       // Time, position, and ID of last message
    ULONG_PTR           idLast;
    int                 cQuit;
    int                 exitCode;
    HANDLE                hdesk;        // Desktop handle. Changed from "HDESK hdesk"
    int                 cPaintsReady;
    unsigned int        cTimersReady;
    PMENUSTATE            pMenuState;
    union {
        PTDB            ptdb;        // Win16Task Schedule data for WOW thread
        PWINDOWSTATION    pwinsta;    // Window station for SYSTEM thread
    };
    PSVR_INSTANCE_INFO     psiiList;   // thread DDEML instance list
    ULONG               dwExpWinVer;
    ULONG               dwCompatFlags;    // The Win 3.1 Compat flags
    ULONG               dwCompatFlags2; // new DWORD to extend compat flags for NT5+ features
    PQ                    pqAttach;    // calculation variabled used in zzzAttachThreadInput()
    void*                ptiSibling;    // Pointer to sibling thread info. Chnaged from "PTHREADINFO ptiSibling"
    PMOVESIZEDATA        pmsd;
    ULONG               fsHooks;    // WHF_ Flags for which hooks are installed
    PHOOK               sphkCurrent;// Hook this thread is currently processing
    PSBTRACK            pSBTrack;
    HANDLE              hEventQueueClient;
    PKEVENT             pEventQueueServer;
    LIST_ENTRY          PtiLink;      // Link to other threads on desktop
    int                 iCursorLevel;   // keep track of each thread's level
    ULONG                b[2];        //POINT           ptLast;
    PWND                spwndDefaultIme;// Default IME Window for this thread
    PIMC                spDefaultImc;    // Default input context for this thread
    HANDLE                hklPrev;    // Previous active. Changed from "HKL hklPrev"
    int                 cEnterCount;
    MLIST               mlPost;     // posted message list.
    int              fsChangeBitsRemoved;// Bits removed during PeekMessage
    int               wchInjected;    // character from last VK_PACKET
    ULONG               fsReserveKeys;  // Keys that must be sent to the active                +E0
    PKEVENT                *apEvent;       // Wait array for xxxPollAndWaitForSingleObject        +E4
    ACCESS_MASK         amdesk;         // Granted access                                    +E8
    unsigned int        cWindows;       // Number of windows owned by this thread            +EC
    unsigned int        cVisWindows;    // Number of visible windows on this thread            +F0
    PHOOK               aphkStart[CWINHOOKS];    // Hooks registered for this thread, local hook    +F4
    CLIENTTHREADINFO    cti;              // Use this when no desktop is available            +F8
} THREADINFO, *PTHREADINFO;

typedef struct _RTL_BALANCED_LINKS {
  struct _RTL_BALANCED_LINKS *Parent;
  struct _RTL_BALANCED_LINKS *LeftChild;
  struct _RTL_BALANCED_LINKS *RightChild;
  CHAR Balance;
  UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
  RTL_BALANCED_LINKS BalancedRoot;
  PVOID OrderedPointer;
  ULONG WhichOrderedElement;
  ULONG NumberGenericTableElements;
  ULONG DepthOfTree;
  PRTL_BALANCED_LINKS RestartKey;
  ULONG DeleteCount;
  PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
  PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
  PRTL_AVL_FREE_ROUTINE FreeRoutine;
  PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

typedef struct _W32PROCESS
{
  PEPROCESS     peProcess;
  DWORD         RefCount;
  ULONG         W32PF_flags;
  PKEVENT       InputIdleEvent;
  DWORD         StartCursorHideTime;
  struct _W32PROCESS * NextStart;
  PVOID         pDCAttrList;
  PVOID         pBrushAttrList;
  DWORD         W32Pid;
  LONG          GDIHandleCount;
  LONG          UserHandleCount;
  PEX_PUSH_LOCK GDIPushLock;  /* Locking Process during access to structure. */
  RTL_AVL_TABLE GDIEngUserMemAllocTable;  /* Process AVL Table. */
  LIST_ENTRY    GDIDcAttrFreeList;
  LIST_ENTRY    GDIBrushAttrFreeList;
} W32PROCESS, *PW32PROCESS;

typedef struct _PROCESSINFO
{
  W32PROCESS;
  PTHREADINFO ptiList;
  PTHREADINFO ptiMainThread;
  struct _DESKTOP* rpdeskStartup;
  PCLS pclsPrivateList;
  PCLS pclsPublicList;
  PWOWPROCESSINFO pwpi;                       // Wow PerProcess Info
  PPROCESSINFO    ppiNext;                    // next ppi structure in start list
  PPROCESSINFO    ppiNextRunning;
  int             cThreads;                   // count of threads using this process info
  HDESK           hdeskStartup;               // initial desktop handle
  UINT            cSysExpunge;                // sys expunge counter
  DWORD dwhmodLibLoadedMask;
  HANDLE ahmodLibLoaded[CLIBS];
  struct _WINSTATION_OBJECT *prpwinsta;
  HWINSTA hwinsta;
  ACCESS_MASK amwinsta;
  DWORD dwHotkey;
  HMONITOR hMonitor;
  LUID luidSession;
  USERSTARTUPINFO usi;
  DWORD dwLayout;
  DWORD dwRegisteredClasses;
  /* ReactOS */
  LIST_ENTRY MenuListHead;
  FAST_MUTEX PrivateFontListLock;
  LIST_ENTRY PrivateFontListHead;
  FAST_MUTEX DriverObjListLock;
  LIST_ENTRY DriverObjListHead;
  struct _KBL* KeyboardLayout; // THREADINFO only
  W32HEAP_USER_MAPPING HeapMappings;
} PROCESSINFO;

PTHREADINFO NTAPI PsGetThreadWin32Thread(IN PETHREAD Thread);

