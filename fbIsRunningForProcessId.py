from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fbIsRunningForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, SYNCHRONIZE, bMustExists = False);
  if not fbIsValidHandle(hProcess):
    return False;
  bSuccess = False;
  try:
    bResult = fbIsRunningForProcessHandle(hProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return bResult;