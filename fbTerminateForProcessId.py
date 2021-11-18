from mWindowsSDK import *;
from .fbIsRunningForProcessId import fbIsRunningForProcessId;
from .fbIsValidHandle import fbIsValidHandle;
from .fbTerminateForProcessHandle import fbTerminateForProcessHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbTerminateForProcessId(uProcessId, nTimeoutInSeconds = None, bWait = True):
  # Try to open the process so we can terminate it...
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(ohProcess):
    return True; # No process with the given id exists.
  bSuccess = False;
  try:
    # We can open the process: try to terminate it.
    bResult = fbTerminateForProcessHandle(ohProcess, nTimeoutInSeconds, bWait = bWait);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return bResult;