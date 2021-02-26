from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fdsGetProcessesExecutableName_by_uId import fdsGetProcessesExecutableName_by_uId;
from .fThrowWin32Error import fThrowWin32Error;

def fohOpenForProcessIdAndDesiredAccess(uProcessId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = oKernel32.OpenProcess(DWORD(uDesiredAccess), BOOLEAN(bInheritHandle), DWORD(uProcessId));
  if not fbIsValidHandle(ohProcess):
    # Save the last error because want to check if the process is running, which may fail and modify it.
    uLastError = oKernel32.GetLastError().fuGetValue()
    if not bMustExist and uProcessId not in fdsGetProcessesExecutableName_by_uId():
      return HANDLE(INVALID_HANDLE_VALUE); # No process exists; return an invalid handle
    # The process exists; report an error:
    fThrowWin32Error(
      "OpenProcess(0x%08X, FALSE, 0x%X)" % (uDesiredAccess, uProcessId, uProcessId),
      uLastError
    );
  return ohProcess;