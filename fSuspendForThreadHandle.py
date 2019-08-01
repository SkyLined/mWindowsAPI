from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;

def fSuspendForThreadHandle(ohThread):
  if oKernel32.SuspendThread(ohThread) == -1:
    fThrowLastError("SuspendThread(0x%08X)" % (ohThread.value,));
