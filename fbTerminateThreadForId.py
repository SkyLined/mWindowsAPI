from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

def fbTerminateThreadForId(uThreadId):
  hThread = KERNEL32.OpenThread(THREAD_TERMINATE, FALSE, uThreadId);
  if not hThread:
    return False;
  try:
    assert KERNEL32.TerminateThread(hThread), \
        fsGetErrorMessage("TerminateThread(0x%X)" % (hThread.value,));
    return True;
  finally:
    assert KERNEL32.CloseHandle(hThread), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hThread.value,));
