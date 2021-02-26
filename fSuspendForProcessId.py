from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fSuspendForProcessHandle import fSuspendForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fSuspendForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  oNTDLL = foLoadNTDLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  bSuccess = False;
  try:
    fSuspendForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
