from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowWin32Error import fThrowWin32Error;
from .fThrowLastError import fThrowLastError;

def fDebugBreakForProcessId(uProcessId):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_ALL_ACCESS);
  if not oKernel32DLL.DebugBreakProcess(ohProcess):
    # Save the last error because want to close the process handle, which may fail and modify it.
    uLastError = oKernel32DLL.GetLastError().fuGetValue();
    oKernel32DLL.CloseHandle(ohProcess);
    fThrowWin32Error(
      "DebugBreakProcess(%s)" % (repr(ohProcess),),
      uLastError
    );
  if not oKernel32DLL.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
