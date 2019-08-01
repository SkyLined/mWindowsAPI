from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fbIsValidHandle import fbIsValidHandle;
from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbIsRunningForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, SYNCHRONIZE, bMustExists = False);
  if not fbIsValidHandle(ohProcess):
    return False;
  bSuccess = False;
  try:
    bResult = fbIsRunningForProcessHandle(ohProcess);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return bResult;