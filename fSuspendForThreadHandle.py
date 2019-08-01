from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fSuspendForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  if oKernel32.SuspendThread(ohThread) == -1:
    fThrowLastError("SuspendThread(0x%08X)" % (ohThread.value,));
