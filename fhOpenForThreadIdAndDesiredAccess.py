from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fhOpenForThreadIdAndDesiredAccess(uThreadId, uDesiredAccess, bInheritHandle = False, bMustExist = True):
  hThread = KERNEL32.OpenThread(DWORD(uDesiredAccess), bInheritHandle, DWORD(uThreadId));
  if not fbIsValidHandle(hThread):
    # Save the last error because want to check if the thread exists, which may fail and modify it.
    dwLastError = KERNEL32.GetLastError();
    if not bMustExist: # TODO! Checking if the thread exists is not implemented
      return HANDLE(INVALID_HANDLE_VALUE); # No such thread exists; return an invalid handle
    # The thread exists; report an error:
    fThrowError("OpenThread(0x%08X, FALSE, %d/0x%X)" % (uDesiredAccess, uThreadId, uThreadId), dwLastError.value);
  return hThread;