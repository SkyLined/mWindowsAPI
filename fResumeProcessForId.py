from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from fThrowError import fThrowError;

def fResumeProcessForId(uProcessId):
  uFlags = THREAD_SUSPEND_RESUME;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
      or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    hResult = NTDLL.NtResumeProcess(hProcess); # NOT RELIABLE!
    SUCCEEDED(hResult) \
        or fThrowError("NtResumeProcess(0x%08X) == %08X" % (hProcess.value, hResult.value,));
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess.value,));
