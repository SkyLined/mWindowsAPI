from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fTerminateThreadForHandle(hThread):
  KERNEL32.TerminateThread(hThread) \
      or fThrowError("TerminateThread(0x%X)" % (hThread.value,));
