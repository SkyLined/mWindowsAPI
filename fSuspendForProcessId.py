from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fSuspendForProcessHandle import fSuspendForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fSuspendForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_SUSPEND_RESUME);
  try:
    fSuspendForProcessHandle(ohProcess);
  except:
    oKernel32DLL.CloseHandle(ohProcess);
    raise;
  if not oKernel32DLL.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
