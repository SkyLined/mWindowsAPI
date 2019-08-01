from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fbResumeForThreadHandle(ohThread):
  # A thread can be suspended multiple times. This function returns True if the thread is suspended 0 times after
  # returning.
  oKernel32 = foLoadKernel32DLL();
  odwSuspendCount = oKernel32.ResumeThread(ohThread);
  if odwSuspendCount == DWORD(-1):
    fThrowLastError("ResumeThread(0x%08X) == -1" % (ohThread.value,));
  return odwSuspendCount.value == 0;