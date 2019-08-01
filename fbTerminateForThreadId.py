from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsValidHandle import fbIsValidHandle;
from .fbTerminateForThreadHandle import fbTerminateForThreadHandle;
from .fohOpenForThreadIdAndDesiredAccess import fohOpenForThreadIdAndDesiredAccess;
from .fThrowError import fThrowError;

def fbTerminateForThreadId(uThreadId, nTimeoutInSeconds = None, bWait = True):
  # Try to open the thread so we can terminate it...
  ohThread = fohOpenForThreadIdAndDesiredAccess(uThreadId, THREAD_TERMINATE | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(ohThread):
    return True; # No thread with the given id exists.
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbTerminateForThreadHandle(ohThread, nTimeoutInSeconds, bWait = bWait);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohThread.value,));
  return bResult;
