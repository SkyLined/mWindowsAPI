from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForProcessHandle import fuGetExitCodeForProcessHandle;

def fuGetExitCodeForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
  bSuccess = False;
  try:
    uProcessExitCode = fuGetExitCodeForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return uProcessExitCode;