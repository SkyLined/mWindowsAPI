from .fThrowLastError import fThrowLastError;
from .fthuCreateThreadForProcessIdAndAddress import fthuCreateThreadForProcessIdAndAddress;
from .mDLLs import KERNEL32;

def fuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments):
  (hThread, uThreadId) = fthuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments);
  if not KERNEL32.CloseHandle(hThread):
    fThrowLastError("CloseHandle(0x%08X)" % (hThread.value,));
  return uThreadId;