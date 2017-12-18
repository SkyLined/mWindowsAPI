from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from fThrowError import fThrowError;

def fSuspendProcessForId(uProcessId):
  uFlags = THREAD_SUSPEND_RESUME;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
      or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    hResult = NTDLL.NtSuspendProcess(hProcess);
    SUCCEEDED(hResult) \
        or fThrowError("NtSuspendProcess(0x%08X) == %08X" % (hProcess.value, hResult.value,));
    return True;
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess.value,));
