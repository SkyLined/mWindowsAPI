from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .fuGetIntegrityLevelForProcessHandle import fuGetIntegrityLevelForProcessHandle;
from .mDefines import *;
from .mDLLs import ADVAPI32, KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fuGetIntegrityLevelForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_INFORMATION);
  bSuccess = False;
  try:
    uIntegrityLevel = fuGetIntegrityLevelForProcessHandle(hProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%08X)" % (hProcess.value,));
  return uIntegrityLevel;
