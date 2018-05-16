from .mDefines import FALSE, THREAD_SUSPEND_RESUME;
from .mFunctions import SUCCEEDED;
from .mDLLs import KERNEL32, NTDLL;
from .fThrowError import fThrowError;

def fSuspendProcessForId(uProcessId):
  uFlags = THREAD_SUSPEND_RESUME;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
      or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    uNTStatus = NTDLL.NtSuspendProcess(hProcess); # NOT RELIABLE!
    SUCCEEDED(uNTStatus) \
        or fThrowError("NtSuspendProcess(0x%08X)" % (hProcess.value,), uNTStatus.value);
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess.value,));
