from .fbIsRunningForThreadId import fbIsRunningForThreadId;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fThrowError import fThrowError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fbWaitForTerminationForThreadId(uThreadId, nTimeoutInSeconds = None):
  # Try to open the thread so we can wait for it...
  hThread = fhOpenForThreadIdAndDesiredAccess(uThreadId, SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(hThread):
    return True; # No thread with the given id exists.
  bSuccess = False;
  try:
    bResult = fbWaitForTerminationForThreadHandle(hThread, nTimeoutInSeconds);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hThread.value,));
  return bResult;
