from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsValidHandle import fbIsValidHandle;
from .fThrowError import fThrowError;

def fohOpenForThreadIdAndDesiredAccess(uThreadId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  ohThread = oKernel32.OpenThread(DWORD(uDesiredAccess), BOOLEAN(bInheritHandle), DWORD(uThreadId));
  if not fbIsValidHandle(ohThread):
    # Save the last error because want to check if the thread exists, which may fail and modify it.
    odwLastError = oKernel32.GetLastError();
    if not bMustExist: # TODO! Checking if the thread exists is not implemented
      return HANDLE(INVALID_HANDLE_VALUE); # No such thread exists; return an invalid handle
    # The thread exists; report an error:
    fThrowError("OpenThread(0x%08X, FALSE, %d/0x%X)" % (uDesiredAccess, uThreadId, uThreadId), odwLastError.value);
  return ohThread;