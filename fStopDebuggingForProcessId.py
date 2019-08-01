from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;

def fStopDebuggingForProcessId(uProcessId):
  if not oKernel32.DebugActiveProcessStop(uProcessId):
    fThrowLastError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
