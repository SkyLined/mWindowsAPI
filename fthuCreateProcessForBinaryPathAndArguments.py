from .fThrowError import fThrowError;
from .fthuhuCreateProcessAndThreadForBinaryPathAndArguments import fthuhuCreateProcessAndThreadForBinaryPathAndArguments;
from .mDLLs import KERNEL32;

def fthuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (hProcess, uProcessId, hThread, uThreadId) = fthuhuCreateProcessAndThreadForBinaryPathAndArguments(*txArguments, **dxArguments);
  if hProcess is None: # Cannot start because path is invalid or not found.
    return (None, None);
  if not KERNEL32.CloseHandle(hThread):
    # Save the last error because want to try to close the process handle, which may fail and modify it.
    dwLastError = KERNEL32.GetLastError();
    KERNEL32.CloseHandle(hProcess);
    fThrowError("CloseHandle(0x%X)" % (hThread.value,), dwLastError.value);
  return (hProcess, uProcessId);