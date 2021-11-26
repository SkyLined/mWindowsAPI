from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetIntegrityLevelForProcessHandle import fuGetIntegrityLevelForProcessHandle;

def fuGetIntegrityLevelForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_INFORMATION);
  bSuccess = False;
  try:
    uIntegrityLevel = fuGetIntegrityLevelForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uIntegrityLevel;
