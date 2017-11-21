from cDLL import cDLL;
from PrimitiveTypes import *;
from StructureTypes import *;

NTDLL = cDLL("ntdll.dll");

NTDLL.fDefineFunction(HRESULT,    "NtSuspendProcess", HANDLE);
NTDLL.fDefineFunction(BOOL,       "ZwQueryInformationProcess", HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);