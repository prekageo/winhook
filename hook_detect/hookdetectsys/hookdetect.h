typedef DWORD (NTAPI *UserGetAtomName_ptr)(ATOM nAtom, LPWSTR lpBuffer, DWORD dwBufferSize);
NTSTATUS PsLookupThreadByThreadId(__in   HANDLE ThreadId,__out  PETHREAD *Thread);
