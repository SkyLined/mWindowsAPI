from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fhOpenForProcessIdAndDesiredAccess(uProcessId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  hProcess = KERNEL32.OpenProcess(DWORD(uDesiredAccess), bInheritHandle, DWORD(uProcessId));
  if not fbIsValidHandle(hProcess):
    # Save the last error because want to check if the process is running, which may fail and modify it.
    dwLastError = KERNEL32.GetLastError();
    if not bMustExist and uProcessId not in fdsProcessesExecutableName_by_uId():
      return HANDLE(INVALID_HANDLE_VALUE); # No process exists; return an invalid handle
    # The process exists; report an error:
    fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uDesiredAccess, uProcessId, uProcessId), dwLastError.value);
  return hProcess;