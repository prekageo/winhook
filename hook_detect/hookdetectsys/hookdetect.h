typedef DWORD (NTAPI *UserGetAtomName_ptr)(ATOM nAtom, LPWSTR lpBuffer, DWORD dwBufferSize);
NTSTATUS PsLookupThreadByThreadId(__in   HANDLE ThreadId,__out  PETHREAD *Thread);
DWORD PsGetThreadSessionId(__in   PETHREAD Thread);
DWORD PsGetCurrentProcessSessionId();
