from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;

def fSuspendForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  oNTDLL = foLoadNTDLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  bSuccess = False;
  try:
    oNTStatus = oNTDLL.NtSuspendProcess(ohProcess); # NOT RELIABLE!
    if NT_ERROR(oNTStatus):
      fThrowError("NtSuspendProcess(0x%08X)" % (ohProcess.value,), oNTStatus.value);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
