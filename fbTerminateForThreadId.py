from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fbTerminateForThreadHandle import fbTerminateForThreadHandle;
from .foh0OpenForThreadIdAndDesiredAccess import foh0OpenForThreadIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbTerminateForThreadId(uThreadId, nTimeoutInSeconds = None, bWait = True):
  # Try to open the thread so we can terminate it...
  oh0Thread = foh0OpenForThreadIdAndDesiredAccess(uThreadId, THREAD_TERMINATE | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, bMustExist = False);
  if oh0Thread is None:
    return True; # No thread with the given id exists.
  ohThread = oh0Thread;
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbTerminateForThreadHandle(ohThread, nTimeoutInSeconds, bWait = bWait);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohThread),));
  return bResult;
