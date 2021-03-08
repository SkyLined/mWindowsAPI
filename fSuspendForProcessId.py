from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fSuspendForProcessHandle import fSuspendForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fSuspendForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_SUSPEND_RESUME);
  try:
    fSuspendForProcessHandle(ohProcess);
  except:
    oKernel32.CloseHandle(ohProcess);
    raise;
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
