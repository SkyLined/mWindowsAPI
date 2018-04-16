from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fbIsProcessRunningForHandle import fbIsProcessRunningForHandle;
from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from .fThrowError import fThrowError;

def fbIsProcessRunningForId(uProcessId):
  # Try to open the process so we can terminate it...
  uFlags = SYNCHRONIZE;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  if not hProcess:
    # We cannot open the process: the process may have terminated so long ago that it's process id is no longer valid:
    uOpenProcessError = KERNEL32.GetLastError();
    (HRESULT_FROM_WIN32(uOpenProcessError) == ERROR_INVALID_PARAMETER) \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId), uOpenProcessError);
    (uProcessId not in fdsProcessesExecutableName_by_uId()) \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId), uOpenProcessError);
    # The process does not exist anymore.
    return False;
  try:
    return fbIsProcessRunningForHandle(hProcess);
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
