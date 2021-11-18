from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fsGetISAForProcessHandle import fsGetISAForProcessHandle;
from .fThrowLastError import fThrowLastError;
from .oSystemInfo import oSystemInfo;

def fsGetISAForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
  bSuccess = False;
  try:
    sResult = fsGetISAForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return sResult;
