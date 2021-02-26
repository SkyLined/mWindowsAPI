from mWindowsSDK import *;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fbIsValidHandle import fbIsValidHandle;
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
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return bResult;