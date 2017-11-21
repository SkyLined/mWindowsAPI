from mWindowsAPI import *;

def fDebugBreakProcessForId(uProcessId):
  hProcess = KERNEL32.OpenProcess(0x1F0FFF, FALSE, uProcessId);
  assert hProcess, \
    "OpenProcess(PROCESS_ALL_ACCESS, FALSE, %d/0x%X) => Error 0x%08X." % (uProcessId, uProcessId, KERNEL32.GetLastError());
  try:
    assert KERNEL32.DebugBreakProcess(hProcess), \
        "DebugBreakProcess(0x%08X) => Error %08X." % (hProcess, KERNEL32.GetLastError());
    return True;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
