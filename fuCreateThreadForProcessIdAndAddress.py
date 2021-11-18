from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateThreadForProcessIdAndAddress import ftohuCreateThreadForProcessIdAndAddress;

def fuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  (ohThread, uThreadId) = ftohuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments);
  if not oKernel32DLL.CloseHandle(ohThread):
    fThrowLastError("CloseHandle(%s)" % (repr(ohThread),));
  return uThreadId;