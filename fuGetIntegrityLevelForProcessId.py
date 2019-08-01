from mWindowsSDK import *;
from .mDLLs import oKernel32;
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
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%08X)" % (ohProcess.value,));
  return uIntegrityLevel;
