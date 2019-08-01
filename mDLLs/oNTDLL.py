from mWindowsSDK import *;

oNTDLL = cDLL(
  "ntdll.dll",
  {
    "NtResumeProcess": {
      "xReturnType": NTSTATUS,    
      "txArgumentTypes": (HANDLE,),
    },
    "NtSuspendProcess": {
      "xReturnType": NTSTATUS,    
      "txArgumentTypes": (HANDLE,),
    },
    "NtQueryInformationProcess": {
      "xReturnType": NTSTATUS,   
      "txArgumentTypes": (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG),
    },
    "NtQueryInformationThread": {
      "xReturnType": NTSTATUS,   
      "txArgumentTypes": (HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG),
    },
  },
);