from .fbIsRunningForProcessId import fbIsRunningForProcessId;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fbWaitForTerminationForProcessId(uProcessId, nTimeoutInSeconds = None):
  # Try to open the process so we can wait for it...
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, SYNCHRONIZE, bMustExists = False);
  if not fbIsValidHandle(hProcess):
    return True; # No process exists with this id.
  bSuccess = False;
  try:
    bResult = fbWaitForTerminationForProcessHandle(hProcess, nTimeoutInSeconds);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return bResult;
