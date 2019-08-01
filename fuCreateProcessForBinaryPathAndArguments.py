from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateProcessForBinaryPathAndArguments import ftohuCreateProcessForBinaryPathAndArguments;

def fuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (ohProcess, uProcessId) = ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return None;
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return uProcessId;