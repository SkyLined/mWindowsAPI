from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;

def fDebugBreakForProcessId(uProcessId):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_ALL_ACCESS);
  if not oKernel32.DebugBreakProcess(ohProcess):
    # Save the last error because want to close the process handle, which may fail and modify it.
    odwLastError = oKernel32.GetLastError();
    oKernel32.CloseHandle(ohProcess);
    fThrowError("DebugBreakProcess(0x%08X)" % (ohProcess.value,), odwLastError.value);
  if not oKernel32.CloseHandle(ohProcess):
    fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
