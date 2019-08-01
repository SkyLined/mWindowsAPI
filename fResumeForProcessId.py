from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;

def fResumeForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  oNTDLL = foLoadNTDLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  ohResult = oNTDLL.NtResumeProcess(ohProcess); # NOT RELIABLE!
  if FAILED(ohResult):
    # Save the last error because want to close the process handle, which may fail and modify it.
    odwLastError = oKernel32.GetLastError();
    oKernel32.CloseHandle(ohProcess);
    fThrowError("NtResumeProcess(0x%08X) == %08X" % (ohProcess.value, ohResult.value,), odwLastError.value);
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
