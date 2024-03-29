from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsRunningForThreadId import fbIsRunningForThreadId;
from .fbIsValidHandle import fbIsValidHandle;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .foh0OpenForThreadIdAndDesiredAccess import foh0OpenForThreadIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbWaitForTerminationForThreadId(uThreadId, nTimeoutInSeconds = None):
  # Try to open the thread so we can wait for it...
  oh0Thread = foh0OpenForThreadIdAndDesiredAccess(uThreadId, SYNCHRONIZE, bMustExist = False);
  if oh0Thread is None:
    return True; # No thread with the given id exists.
  bSuccess = False;
  try:
    bResult = fbWaitForTerminationForThreadHandle(ohThread, nTimeoutInSeconds);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32DLL.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohThread),));
  return bResult;
