from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;
from .fThrowError import fThrowError;

def fuGetExitCodeForThreadHandle(hThread):
  if fbIsRunningForThreadHandle(hThread):
    # Still running; no exit code.
    return None;
  dwExitCode = DWORD();
  if not KERNEL32.GetExitCodeThread(hThread, POINTER(dwExitCode)):
    fThrowLastError("GetExitCodeThread(0x%08X, 0x%X)" % (hThread.value, fuAddressOf(dwExitCode)));
  return dwExitCode.value;
