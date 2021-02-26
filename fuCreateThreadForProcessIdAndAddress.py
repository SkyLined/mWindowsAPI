from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateThreadForProcessIdAndAddress import ftohuCreateThreadForProcessIdAndAddress;

def fuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments):
  oKernel32 = foLoadKernel32DLL();
  (ohThread, uThreadId) = ftohuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments);
  if not oKernel32.CloseHandle(ohThread):
    fThrowLastError("CloseHandle(%s)" % (repr(ohThread),));
  return uThreadId;