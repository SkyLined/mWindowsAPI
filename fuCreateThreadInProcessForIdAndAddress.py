from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

def fuCreateThreadInProcessForIdAndAddress(uProcessId, uAddress, bSuspended = False):
  uFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  assert hProcess, \
      fsGetErrorMessage("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId));
  try:
    uThreadId = DWORD();
    hThread = KERNEL32.CreateRemoteThread(
      hProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      CAST(LPTHREAD_START_ROUTINE, uAddress), # lpStartAddress
      0, # lpParameter
      bSuspended and CREATE_SUSPENDED or 0, # dwCreationFlags
      POINTER(uThreadId), # lpThreadId
    );
    assert hThread, \
        fsGetErrorMessage("CreateRemoteThread(0x%08X, NULL, 0, 0x%08X, 0, 0, ...)" % (hProcess.value, uAddress));
    assert KERNEL32.CloseHandle(hThread), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hThread.value,));
    return uThreadId.value;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
