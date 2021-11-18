from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fbSuspendForThreadHandle(ohThread):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  odwSuspendCount = oKernel32DLL.SuspendThread(ohThread);
  if odwSuspendCount.fiGetValue() == -1:
    fThrowLastError("SuspendThread(%s)" % (repr(ohThread),));
  return odwSuspendCount.value == 0;
