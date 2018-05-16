from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fbResumeThreadForHandle(hThread):
  iSuspendCount = KERNEL32.ResumeThread(hThread);
  iSuspendCount != -1 \
      or fThrowError("ResumeThread(0x%08X) == -1" % (hThread,));
  return iSuspendCount == 0;