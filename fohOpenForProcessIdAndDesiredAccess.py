from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from .fThrowLastError import fThrowLastError;

def fohOpenForProcessIdAndDesiredAccess(uProcessId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = oKernel32.OpenProcess(DWORD(uDesiredAccess), BOOLEAN(bInheritHandle), DWORD(uProcessId));
  if not fbIsValidHandle(ohProcess):
    # Save the last error because want to check if the process is running, which may fail and modify it.
    odwLastError = oKernel32.GetLastError();
    if not bMustExist and uProcessId not in fdsProcessesExecutableName_by_uId():
      return HANDLE(INVALID_HANDLE_VALUE); # No process exists; return an invalid handle
    # The process exists; report an error:
    fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uDesiredAccess, uProcessId, uProcessId), odwLastError.value);
  return ohProcess;