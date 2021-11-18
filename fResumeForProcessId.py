from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowNTStatusError import fThrowNTStatusError;
from .fThrowLastError import fThrowLastError;

def fResumeForProcessId(uProcessId):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  oNTDLL = foLoadNTDLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  oNTStatus = oNTDLL.NtResumeProcess(ohProcess); # NOT RELIABLE!
  if not NT_SUCCESS(oNTStatus):
    # Save the last error because want to close the process handle, which may fail and modify it.
    oKernel32DLL.CloseHandle(ohProcess);
    fThrowNTStatusError(
      "NtResumeProcess(%s)" % (repr(ohProcess),),
      oNTStatus.fuGetValue()
    );
  if not oKernel32DLL.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
