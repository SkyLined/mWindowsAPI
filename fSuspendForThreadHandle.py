from .fThrowLastError import fThrowLastError;
from .mDLLs import KERNEL32;

def fSuspendForThreadHandle(hThread):
  if KERNEL32.SuspendThread(hThread) == -1:
    fThrowLastError("SuspendThread(0x%08X)" % (hThread.value,));
