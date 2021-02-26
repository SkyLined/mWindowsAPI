from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowWin32Error import fThrowWin32Error;
from .fThrowLastError import fThrowLastError;

def fDebugBreakForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_ALL_ACCESS);
  if not oKernel32.DebugBreakProcess(ohProcess):
    # Save the last error because want to close the process handle, which may fail and modify it.
    uLastError = oKernel32.GetLastError().fuGetValue();
    oKernel32.CloseHandle(ohProcess);
    fThrowWin32Error(
      "DebugBreakProcess(%s)" % (repr(ohProcess),),
      uLastError
    );
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
