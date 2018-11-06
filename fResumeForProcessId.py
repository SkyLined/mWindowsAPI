from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32, NTDLL;
from .mFunctions import *;
from .mTypes import *;

def fResumeForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  hResult = NTDLL.NtResumeProcess(hProcess); # NOT RELIABLE!
  if not SUCCEEDED(hResult):
    # Save the last error because want to close the process handle, which may fail and modify it.
    dwLastError = KERNEL32.GetLastError();
    KERNEL32.CloseHandle(hProcess);
    fThrowError("NtResumeProcess(0x%08X) == %08X" % (hProcess.value, hResult.value,), dwLastError.value);
  if not KERNEL32.CloseHandle(hProcess):
    fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
