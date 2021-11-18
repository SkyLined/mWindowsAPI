from .fThrowWin32Error import fThrowWin32Error;
from .ftohuohuCreateProcessAndThreadForBinaryPathAndArguments import ftohuohuCreateProcessAndThreadForBinaryPathAndArguments;

def ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (ohProcess, uProcessId, ohThread, uThreadId) = ftohuohuCreateProcessAndThreadForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return (None, None);
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  if not oKernel32DLL.CloseHandle(ohThread):
    # Save the last error because want to try to close the process handle, which may fail and modify it.
    uLastError = oKernel32DLL.GetLastError().fuGetValue();
    oKernel32DLL.CloseHandle(ohProcess);
    fThrowWin32Error(
      "CloseHandle(%s)" % (repr(ohThread),),
      uLastError
    );
  return (ohProcess, uProcessId);