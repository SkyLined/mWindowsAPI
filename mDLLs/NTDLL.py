from cDLL import cDLL;
from ..mTypes import *;

NTDLL = cDLL("ntdll.dll");

NTDLL.fDefineFunction(HRESULT,    "NtSuspendProcess", HANDLE);
NTDLL.fDefineFunction(BOOL,       "ZwQueryInformationProcess", HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);