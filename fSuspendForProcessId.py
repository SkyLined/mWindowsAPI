from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32, NTDLL;
from .mFunctions import *;

def fSuspendForProcessId(uProcessId):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, THREAD_SUSPEND_RESUME);
  bSuccess = False;
  try:
    oNTStatus = NTDLL.NtSuspendProcess(hProcess); # NOT RELIABLE!
    if not SUCCEEDED(oNTStatus):
      fThrowError("NtSuspendProcess(0x%08X)" % (hProcess.value,), oNTStatus.value);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
