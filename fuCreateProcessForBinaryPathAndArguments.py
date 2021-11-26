from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateProcessForBinaryPathAndArguments import ftohuCreateProcessForBinaryPathAndArguments;

def fuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (ohProcess, uProcessId) = ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return None;
  if not oKernel32DLL.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uProcessId;