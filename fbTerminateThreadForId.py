from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fbTerminateThreadForId(uThreadId):
  hThread = KERNEL32.OpenThread(THREAD_TERMINATE, FALSE, uThreadId);
  if not hThread:
    return False;
  try:
    KERNEL32.TerminateThread(hThread) \
        or fThrowError("TerminateThread(0x%X)" % (hThread.value,));
  finally:
    KERNEL32.CloseHandle(hThread) \
        or fThrowError("CloseHandle(0x%X)" % (hThread.value,));
  return True;
