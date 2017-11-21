from mWindowsAPI import *;

def fbTerminateThreadForId(uThreadId):
  hThread = KERNEL32.OpenThread(THREAD_TERMINATE, FALSE, uThreadId);
  if not hThread:
    return False;
  try:
    assert KERNEL32.TerminateThread(hThread), \
        "TerminateThread(0x%X) => Error 0x%08X" % (hThread, KERNEL32.GetLastError());
    return True;
  finally:
    assert KERNEL32.CloseHandle(hThread), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hThread, KERNEL32.GetLastError());
