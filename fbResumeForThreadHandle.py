from .fThrowLastError import fThrowLastError;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbResumeForThreadHandle(hThread):
  # A thread can be suspended multiple times. This function returns True if the thread is suspended 0 times after
  # returning.
  dwSuspendCount = KERNEL32.ResumeThread(hThread);
  if dwSuspendCount.value == DWORD(-1).value:
    fThrowLastError("ResumeThread(0x%08X) == -1" % (hThread.value,));
  return dwSuspendCount.value == 0;