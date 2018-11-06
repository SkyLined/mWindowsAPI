from .fbIsRunningForProcessId import fbIsRunningForProcessId;
from .fbTerminateForProcessHandle import fbTerminateForProcessHandle;
from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fbTerminateForProcessId(uProcessId, nTimeoutInSeconds = None, bWait = True):
  # Try to open the process so we can terminate it...
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, bMustExist = False);
  if not fbIsValidHandle(hProcess):
    return True; # No process with the given id exists.
  bSuccess = False;
  try:
    # We can open the process: try to terminate it.
    bResult = fbTerminateForProcessHandle(hProcess, nTimeoutInSeconds, bWait = bWait);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return bResult;