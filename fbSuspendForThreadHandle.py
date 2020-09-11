from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fbSuspendForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  odwSuspendCount = oKernel32.SuspendThread(ohThread);
  if odwSuspendCount.value == -1:
    fThrowLastError("SuspendThread(0x%08X)" % (ohThread.value,));
  return odwSuspendCount.value == 0;
