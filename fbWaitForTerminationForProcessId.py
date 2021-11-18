from mWindowsSDK import *;
from .fbIsRunningForProcessId import fbIsRunningForProcessId;
from .fbIsValidHandle import fbIsValidHandle;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbWaitForTerminationForProcessId(uProcessId, nTimeoutInSeconds = None):
  # Try to open the process so we can wait for it...
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(ohProcess):
    return True; # No process exists with this id.
  bSuccess = False;
  try:
    bResult = fbWaitForTerminationForProcessHandle(ohProcess, nTimeoutInSeconds);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return bResult;
