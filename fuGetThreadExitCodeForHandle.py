from .mDefines import STILL_ACTIVE;
from .mFunctions import POINTER;
from .mTypes import DWORD;
from .mDLLs import KERNEL32;
from .fbIsThreadRunningForHandle import fbIsThreadRunningForHandle;
from .fThrowError import fThrowError;

def fuGetThreadExitCodeForHandle(hThread):
  dwExitCode = DWORD();
  KERNEL32.GetExitCodeThread(hThread, POINTER(dwExitCode)) \
      or fThrowError("GetExitCodeThread(0x%08X, ...)" % (hThread,));
  uExitCode = dwExitCode.value;
  if uExitCode == STILL_ACTIVE and fbIsThreadRunningForHandle(hThread):
    # The thread is still running.
    return None;
  return uExitCode;
