from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateProcessForBinaryPathAndArguments import ftohuCreateProcessForBinaryPathAndArguments;

def fuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  oKernel32 = foLoadKernel32DLL();
  (ohProcess, uProcessId) = ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return None;
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uProcessId;