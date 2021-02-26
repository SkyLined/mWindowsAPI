from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fsGetThreadAccessRightsFlagsDescription import fsGetThreadAccessRightsFlagsDescription;
from .fThrowWin32Error import fThrowWin32Error;

def foh0OpenForThreadIdAndDesiredAccess(uThreadId, uDesiredAccess, bInheritHandle = False, bMustExist = True, bMustGetAccess = True):
  oKernel32 = foLoadKernel32DLL();
  odwDesiredAccess = DWORD(uDesiredAccess);
  odwThreadId = DWORD(uThreadId);
  ohThread = oKernel32.OpenThread(odwDesiredAccess, BOOLEAN(bInheritHandle), odwThreadId);
  if not fbIsValidHandle(ohThread):
    # Save the last error because want to check if the thread exists, which may fail and modify it.
    uLastError = oKernel32.GetLastError().fuGetValue();
    if not bMustGetAccess and uLastError == ERROR_ACCESS_DENIED:
      return HANDLE(INVALID_HANDLE_VALUE); # Cannot get the requested access to the thread; return an invalid handle
    if not bMustExist and uLastError == ERROR_INVALID_PARAMETER:
      return None; # No such thread exists; return None
    # The thread exists; report an error:
    sDesiredAccess = fsGetThreadAccessRightsFlagsDescription(uDesiredAccess);
    fThrowWin32Error(
      "OpenThread(%s (%s), FALSE, %s)" % (repr(odwDesiredAccess), sDesiredAccess, repr(odwThreadId)),
      uLastError
    );
  return ohThread;
