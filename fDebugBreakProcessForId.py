from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

def fDebugBreakProcessForId(uProcessId):
  uFlags = PROCESS_ALL_ACCESS;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  assert hProcess, \
    fsGetErrorMessage("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId,));
  try:
    assert KERNEL32.DebugBreakProcess(hProcess), \
        fsGetErrorMessage("DebugBreakProcess(0x%08X)" % (hProcess.value,));
    return True;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
