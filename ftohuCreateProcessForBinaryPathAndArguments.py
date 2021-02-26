from .fThrowWin32Error import fThrowWin32Error;
from .ftohuohuCreateProcessAndThreadForBinaryPathAndArguments import ftohuohuCreateProcessAndThreadForBinaryPathAndArguments;
from mWindowsSDK import foLoadKernel32DLL;

def ftohuCreateProcessForBinaryPathAndArguments(*txArguments, **dxArguments):
  (ohProcess, uProcessId, ohThread, uThreadId) = ftohuohuCreateProcessAndThreadForBinaryPathAndArguments(*txArguments, **dxArguments);
  if ohProcess is None: # Cannot start because path is invalid or not found.
    return (None, None);
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.CloseHandle(ohThread):
    # Save the last error because want to try to close the process handle, which may fail and modify it.
    uLastError = oKernel32.GetLastError().fuGetValue();
    oKernel32.CloseHandle(ohProcess);
    fThrowWin32Error(
      "CloseHandle(%s)" % (repr(ohThread),),
      uLastError
    );
  return (ohProcess, uProcessId);