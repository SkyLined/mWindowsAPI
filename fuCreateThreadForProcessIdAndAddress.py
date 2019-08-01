from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;
from .ftohuCreateThreadForProcessIdAndAddress import ftohuCreateThreadForProcessIdAndAddress;

def fuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments):
  (ohThread, uThreadId) = ftohuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, **dxArguments);
  if not oKernel32.CloseHandle(ohThread):
    fThrowLastError("CloseHandle(0x%08X)" % (ohThread.value,));
  return uThreadId;