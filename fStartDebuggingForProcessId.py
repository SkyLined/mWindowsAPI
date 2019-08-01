from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;

def fStartDebuggingForProcessId(uProcessId):
  if not oKernel32.DebugActiveProcess(uProcessId):
    fThrowLastError("fStartDebuggingForProcessId(%d/0x%X)" % (uProcessId, uProcessId,));
