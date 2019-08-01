from mWindowsSDK import *;
from .mDLLs import oKernel32;
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
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return sResult;
