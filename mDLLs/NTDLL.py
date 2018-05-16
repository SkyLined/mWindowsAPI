from cDLL import cDLL;
from ..mTypes import *;

NTDLL = cDLL("ntdll.dll");

NTDLL.fDefineFunction(HRESULT,    "NtResumeProcess", HANDLE);
NTDLL.fDefineFunction(HRESULT,    "NtSuspendProcess", HANDLE);
NTDLL.fDefineFunction(NTSTATUS,   "NtQueryInformationProcess", HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTDLL.fDefineFunction(NTSTATUS,   "NtQueryInformationThread", HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
