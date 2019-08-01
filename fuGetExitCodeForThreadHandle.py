from mWindowsSDK import *;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowError import fThrowError;

def fuGetExitCodeForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  if fbIsRunningForThreadHandle(ohThread):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32.GetExitCodeThread(ohThread, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeThread(0x%08X, 0x%X)" % (ohThread.value, odwExitCode.fuGetAddress()));
  return odwExitCode.value;
