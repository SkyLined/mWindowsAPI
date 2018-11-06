from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fsGetISAForProcessHandle import fsGetISAForProcessHandle;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;
from .oSystemInfo import oSystemInfo;

def fsGetISAForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
  bSuccess = False;
  try:
    sResult = fsGetISAForProcessHandle(hProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return sResult;
