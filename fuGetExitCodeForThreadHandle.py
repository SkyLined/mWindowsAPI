from mWindowsSDK import *;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fuGetExitCodeForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  if fbIsRunningForThreadHandle(ohThread):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32.GetExitCodeThread(ohThread, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeThread(%s, 0x%X)" % (repr(ohThread), odwExitCode.fuGetAddress()));
  return odwExitCode.fuGetValue();
