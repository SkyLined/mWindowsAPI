from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForProcessHandle import fuGetExitCodeForProcessHandle;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;

def fuGetExitCodeForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
  bSuccess = False;
  try:
    uProcessExitCode = fuGetExitCodeForProcessHandle(hProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return uProcessExitCode;