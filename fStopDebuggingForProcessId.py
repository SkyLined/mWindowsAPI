from .mDLLs import KERNEL32, NTDLL;
from .fThrowLastError import fThrowLastError;

def fStopDebuggingForProcessId(uProcessId):
  if not KERNEL32.DebugActiveProcessStop(uProcessId):
    fThrowLastError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
