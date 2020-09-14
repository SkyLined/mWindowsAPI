from mWindowsSDK import *;
from .fbIsRunningForThreadId import fbIsRunningForThreadId;
from .fbIsValidHandle import fbIsValidHandle;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .foh0OpenForThreadIdAndDesiredAccess import foh0OpenForThreadIdAndDesiredAccess;
from .fThrowError import fThrowError;

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
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohThread.value,));
  return bResult;
