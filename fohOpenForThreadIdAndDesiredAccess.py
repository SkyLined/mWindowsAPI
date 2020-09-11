from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fsGetThreadAccessRightsFlagsDescription import fsGetThreadAccessRightsFlagsDescription;
from .fThrowError import fThrowError;

def fohOpenForThreadIdAndDesiredAccess(uThreadId, uDesiredAccess, bInheritHandle = False, bMustExist = True, bMustGetAccess = True):
  oKernel32 = foLoadKernel32DLL();
  ohThread = oKernel32.OpenThread(DWORD(uDesiredAccess), BOOLEAN(bInheritHandle), DWORD(uThreadId));
  if not fbIsValidHandle(ohThread):
    # Save the last error because want to check if the thread exists, which may fail and modify it.
    udwLastError = oKernel32.GetLastError().value;
    uhLastError = HRESULT_FROM_WIN32();
    if not bMustGetAccess and uhLastError == ERROR_ACCESS_DENIED:
      return HANDLE(INVALID_HANDLE_VALUE); # Cannot get the requested access to the thread; return an invalid handle
    if not bMustExist and uhLastError == ERROR_INVALID_PARAMETER:
      return HANDLE(INVALID_HANDLE_VALUE); # No such thread exists; return an invalid handle
    # The thread exists; report an error:
    fThrowError(
      "OpenThread(dwDesiredAccess = 0x%08X (%s), bInheritHandle = FALSE, dwThreadId = 0x%X)" % (
        uDesiredAccess,
        fsGetThreadAccessRightsFlagsDescription(uDesiredAccess),
        uThreadId,
      ),
      udwLastError
    );
  return ohThread;
