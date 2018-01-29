from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from cVirtualAllocation import cVirtualAllocation;
from fThrowError import fThrowError;

def fuCreateThreadInProcessForIdAndAddress(uProcessId, uAddress, uParameterAddress = None, bSuspended = False):
  uFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
      or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId));
  try:
    uThreadId = DWORD();
    hThread = KERNEL32.CreateRemoteThread(
      hProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      CAST(LPTHREAD_START_ROUTINE, uAddress), # lpStartAddress
      uParameterAddress, # lpParameter
      bSuspended and CREATE_SUSPENDED or 0, # dwCreationFlags
      POINTER(uThreadId), # lpThreadId
    );
    hThread \
        or fThrowError("CreateRemoteThread(0x%08X, NULL, 0, 0x%08X, 0, 0, ...)" % (hProcess, uAddress));
    KERNEL32.CloseHandle(hThread) \
        or fThrowError("CloseHandle(0x%X)" % (hThread,));
    return uThreadId.value;
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
