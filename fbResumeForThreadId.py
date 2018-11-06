from .fbResumeForThreadHandle import fbResumeForThreadHandle;
from .fhOpenForThreadIdAndDesiredAccess import fhOpenForThreadIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbResumeForThreadId(uThreadId):
  # A thread can be suspended multiple times. This function returns True if the thread is suspended 0 times after
  # returning.
  # Try to open the thread so we can terminate it...
  hThread = fhOpenForThreadIdAndDesiredAccess(uThreadId, THREAD_SUSPEND_RESUME);
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbResumeForThreadHandle(hThread);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hThread.value,));
  return bResult;
