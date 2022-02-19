from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsValidHandle import fbIsValidHandle;
from .fds0GetProcessesExecutableName_by_uId import fds0GetProcessesExecutableName_by_uId;
from .fThrowWin32Error import fThrowWin32Error;

def fohOpenForProcessIdAndDesiredAccess(uProcessId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  odwDesiredAccess = DWORD(uDesiredAccess);
  obInheritHandle = BOOLEAN(bInheritHandle);
  odwProcessId = DWORD(uProcessId);
  ohProcess = oKernel32DLL.OpenProcess(odwDesiredAccess, bInheritHandle, odwProcessId);
  if not fbIsValidHandle(ohProcess):
    # Save the last error because want to check if the process is running, which may fail and modify it.
    uLastError = oKernel32DLL.GetLastError().fuGetValue()
    if not bMustExist and uProcessId not in fds0GetProcessesExecutableName_by_uId():
      return HANDLE(INVALID_HANDLE_VALUE); # No process exists; return an invalid handle
    # The process exists; report an error:
    fThrowWin32Error(
      "OpenProcess(%s, %s, %s)" % (repr(odwDesiredAccess), repr(obInheritHandle), repr(odwProcessId)),
      uLastError
    );
  return ohProcess;