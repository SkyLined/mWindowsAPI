from .fThrowLastError import fThrowLastError;
from .fthuCreateProcessForBinaryPathAndArguments import fthuCreateProcessForBinaryPathAndArguments;
from .mDLLs import KERNEL32;

def fuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (hProcess, uProcessId) = fthuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments);
  if hProcess is None: # Cannot start because path is invalid or not found.
    return None;
  if not KERNEL32.CloseHandle(hProcess):
    fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return uProcessId;