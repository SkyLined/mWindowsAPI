from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fSuspendThreadForHandle(hThread):
  KERNEL32.SuspendThread(hThread) != -1 \
      or fThrowError("SuspendThread(0x%08X)" % (hThread,));
