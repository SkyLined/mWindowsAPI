from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowNTStatusError import fThrowNTStatusError;
from .fThrowLastError import fThrowLastError;

def fResumeForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  oNTDLL = foLoadNTDLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  oNTStatus = oNTDLL.NtResumeProcess(ohProcess); # NOT RELIABLE!
  if not NT_SUCCESS(oNTStatus):
    # Save the last error because want to close the process handle, which may fail and modify it.
    oKernel32.CloseHandle(ohProcess);
    fThrowNTStatusError(
      "NtResumeProcess(%s)" % (repr(ohProcess),),
      oNTStatus.fuGetValue()
    );
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
