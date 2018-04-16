from mDefines import FALSE, PROCESS_QUERY_LIMITED_INFORMATION;
from mDLLs import KERNEL32;
from fbIsProcessRunningForId import fbIsProcessRunningForId;
from fThrowError import fThrowError;
from fuGetProcessExitCodeForHandle import fuGetProcessExitCodeForHandle;

def fuGetProcessExitCodeForId(uProcessId):
  uFlags = PROCESS_QUERY_LIMITED_INFORMATION;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  if not hProcess:
    return None; # Either still running or terminated so long ago that Windows forgot it ever existed.
  try:
    return fuGetProcessExitCodeForHandle(hProcess);
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
