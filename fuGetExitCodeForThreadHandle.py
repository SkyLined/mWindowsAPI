from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowError import fThrowError;

def fuGetExitCodeForThreadHandle(ohThread):
  if fbIsRunningForThreadHandle(ohThread):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32.GetExitCodeThread(ohThread, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeThread(0x%08X, 0x%X)" % (ohThread.value, odwExitCode.fuGetAddress()));
  return odwExitCode.value;
