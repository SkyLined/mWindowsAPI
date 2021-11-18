from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fsGetThreadAccessRightsFlagsDescription import fsGetThreadAccessRightsFlagsDescription;
from .fThrowWin32Error import fThrowWin32Error;

def foh0OpenForThreadIdAndDesiredAccess(uThreadId, uDesiredAccess, bInheritHandle = False, bMustExist = True, bMustGetAccess = True):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  odwDesiredAccess = DWORD(uDesiredAccess);
  obInheritHandle = BOOL(bInheritHandle);
  odwThreadId = DWORD(uThreadId);
  ohThread = oKernel32DLL.OpenThread(odwDesiredAccess, obInheritHandle, odwThreadId);
  if not fbIsValidHandle(ohThread):
    # Save the last error because want to check if the thread exists, which may fail and modify it.
    uLastError = oKernel32DLL.GetLastError().fuGetValue();
    if not bMustGetAccess and uLastError == ERROR_ACCESS_DENIED:
      return HANDLE(INVALID_HANDLE_VALUE); # Cannot get the requested access to the thread; return an invalid handle
    if not bMustExist and uLastError == ERROR_INVALID_PARAMETER:
      return None; # No such thread exists; return None
    # The thread exists; report an error:
    sDesiredAccess = fsGetThreadAccessRightsFlagsDescription(uDesiredAccess);
    fThrowWin32Error(
      "OpenThread(%s (%s), %s, %s)" % (repr(odwDesiredAccess), repr(obInheritHandle), repr(odwThreadId)),
      uLastError
    );
  return ohThread;
