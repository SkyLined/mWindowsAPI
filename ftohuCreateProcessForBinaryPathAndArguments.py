from .fThrowError import fThrowError;
from .ftohuohuCreateProcessAndThreadForBinaryPathAndArguments import ftohuohuCreateProcessAndThreadForBinaryPathAndArguments;

def ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (ohProcess, uProcessId, ohThread, uThreadId) = ftohuohuCreateProcessAndThreadForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return (None, None);
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.CloseHandle(ohThread):
    # Save the last error because want to try to close the process handle, which may fail and modify it.
    odwLastError = oKernel32.GetLastError();
    oKernel32.CloseHandle(ohProcess);
    fThrowError("CloseHandle(0x%X)" % (ohThread.value,), odwLastError.value);
  return (ohProcess, uProcessId);