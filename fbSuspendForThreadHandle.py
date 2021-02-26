from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fbSuspendForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  odwSuspendCount = oKernel32.SuspendThread(ohThread);
  if odwSuspendCount.fiGetValue() == -1:
    fThrowLastError("SuspendThread(%s)" % (repr(ohThread),));
  return odwSuspendCount.value == 0;
