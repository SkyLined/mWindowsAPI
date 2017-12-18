from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fThrowError import fThrowError;

def fDebugBreakProcessForId(uProcessId):
  uFlags = PROCESS_ALL_ACCESS;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
    or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    KERNEL32.DebugBreakProcess(hProcess) \
        or fThrowError("DebugBreakProcess(0x%08X)" % (hProcess.value,));
    return True;
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess.value,));
