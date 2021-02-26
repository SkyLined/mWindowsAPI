from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetIntegrityLevelForProcessHandle import fuGetIntegrityLevelForProcessHandle;

def fuGetIntegrityLevelForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_INFORMATION);
  bSuccess = False;
  try:
    uIntegrityLevel = fuGetIntegrityLevelForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uIntegrityLevel;
