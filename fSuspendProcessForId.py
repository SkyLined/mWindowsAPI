from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from fsGetErrorMessage import fsGetErrorMessage;

def fSuspendProcessForId(uProcessId):
  uFlags = THREAD_SUSPEND_RESUME;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  assert hProcess, \
      fsGetErrorMessage("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    hResult = NTDLL.NtSuspendProcess(hProcess);
    assert SUCCEEDED(hResult), \
        fsGetErrorMessage("NtSuspendProcess(0x%08X) == %08X" % (hProcess.value, hResult.value,));
    return True;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
