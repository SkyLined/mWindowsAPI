from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowLastError import fThrowLastError;

def fbSuspendForThreadHandle(ohThread):
  odwSuspendCount = oKernel32DLL.SuspendThread(ohThread);
  if odwSuspendCount.fiGetValue() == -1:
    fThrowLastError("SuspendThread(%s)" % (repr(ohThread),));
  return odwSuspendCount.value == 0;
