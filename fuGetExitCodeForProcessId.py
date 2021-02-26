from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForProcessHandle import fuGetExitCodeForProcessHandle;

def fuGetExitCodeForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
  bSuccess = False;
  try:
    uProcessExitCode = fuGetExitCodeForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (rep(ohProcess),));
  return uProcessExitCode;