from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fbIsProcessRunningForId import fbIsProcessRunningForId;
from .fbWaitForProcessTerminationForHandle import fbWaitForProcessTerminationForHandle;
from .fThrowError import fThrowError;

def fbWaitForProcessTerminationForId(uProcessId, nTimeout = None):
  if not fbIsProcessRunningForId(uProcessId):
    return True; # Probably already terminated.
  # Try to open the process so we can wait for it...
  uFlags = SYNCHRONIZE;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  if not hProcess:
    uOpenProcessError = KERNEL32.GetLastError();
    # Check again if the process is still running.
    if not fbIsProcessRunningForId(uProcessId):
      return True; # Probably already terminated.
    # The process is running and we cannot open it to terminate it: throw an error.
    fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId), uOpenProcessError);
  try:
    return fbWaitForProcessTerminationForHandle(hProcess, nTimeout);
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
