from .mDefines import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fTerminateThreadForHandle import fTerminateThreadForHandle;
from .fThrowError import fThrowError;

def fbTerminateThreadForId(uThreadId):
  hThread = KERNEL32.OpenThread(THREAD_TERMINATE, FALSE, uThreadId);
  if not hThread:
    return False;
  try:
    fTerminateThreadForHandle(hThread);
  finally:
    KERNEL32.CloseHandle(hThread) \
        or fThrowError("CloseHandle(0x%X)" % (hThread.value,));
  return True;
