from .fbTerminateForThreadHandle import fbTerminateForThreadHandle;
from .fhOpenForThreadIdAndDesiredAccess import fhOpenForThreadIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbTerminateForThreadId(uThreadId, nTimeoutInSeconds = None, bWait = True):
  # Try to open the thread so we can terminate it...
  hThread = fhOpenForThreadIdAndDesiredAccess(uThreadId, THREAD_TERMINATE | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(hThread):
    return True; # No thread with the given id exists.
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbTerminateForThreadHandle(hThread, nTimeoutInSeconds, bWait = bWait);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hThread.value,));
  return bResult;
