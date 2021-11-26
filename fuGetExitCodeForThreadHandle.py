from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fuGetExitCodeForThreadHandle(ohThread):
  if fbIsRunningForThreadHandle(ohThread):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32DLL.GetExitCodeThread(ohThread, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeThread(%s, 0x%X)" % (repr(ohThread), odwExitCode.fuGetAddress()));
  return odwExitCode.fuGetValue();
