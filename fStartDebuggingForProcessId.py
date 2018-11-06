from .mDLLs import KERNEL32, NTDLL;
from .fThrowLastError import fThrowLastError;

def fStartDebuggingForProcessId(uProcessId):
  if not KERNEL32.DebugActiveProcess(uProcessId):
    fThrowLastError("fStartDebuggingForProcessId(%d/0x%X)" % (uProcessId, uProcessId,));
