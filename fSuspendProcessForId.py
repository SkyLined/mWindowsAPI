from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;

def fSuspendProcessForId(uProcessId):
  hProcess = KERNEL32.OpenProcess(THREAD_SUSPEND_RESUME, FALSE, uProcessId);
  assert hProcess, \
      "OpenProcess(PROCESS_ALL_ACCESS, FALSE, %d/0x%X) => Error 0x%08X." % (uProcessId, uProcessId, KERNEL32.GetLastError());
  try:
    hResult = NTDLL.NtSuspendProcess(hProcess);
    assert SUCCEEDED(hResult), \
        "NtSuspendProcess(0x%08X) == %08X => Error %08X." % (hProcess, hResult, KERNEL32.GetLastError());
    return True;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
