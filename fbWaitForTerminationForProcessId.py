from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsRunningForProcessId import fbIsRunningForProcessId;
from .fbIsValidHandle import fbIsValidHandle;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;

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
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return bResult;
