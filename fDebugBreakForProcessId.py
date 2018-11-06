from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fDebugBreakForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_ALL_ACCESS);
  if not KERNEL32.DebugBreakProcess(hProcess):
    # Save the last error because want to close the process handle, which may fail and modify it.
    dwLastError = KERNEL32.GetLastError();
    KERNEL32.CloseHandle(hProcess);
    fThrowError("DebugBreakProcess(0x%08X)" % (hProcess.value,), dwLastError.value);
  if not KERNEL32.CloseHandle(hProcess):
    fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
