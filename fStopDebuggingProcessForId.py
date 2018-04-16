from .mDLLs import KERNEL32, NTDLL;
from .fThrowError import fThrowError;

def fStopDebuggingProcessForId(uProcessId):
  KERNEL32.DebugActiveProcessStop(uProcessId) \
      or fThrowError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
