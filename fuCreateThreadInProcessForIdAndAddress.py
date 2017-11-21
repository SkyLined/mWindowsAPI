from mWindowsAPI import *;

def fuCreateThreadInProcessForIdAndAddress(uProcessId, uAddress, bSuspended = False):
  hProcess = KERNEL32.OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | \
      PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, uProcessId);
  assert hProcess, \
      "OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | " \
      "PROCESS_VM_READ, FALSE, %d/0x%X) => Error 0x%08X." % (uProcessId, uProcessId, KERNEL32.GetLastError());
  try:
    uThreadId = DWORD();
    hThread = KERNEL32.CreateRemoteThread(
      hProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      CAST(LPTHREAD_START_ROUTINE, uAddress), # lpStartAddress
      0, # lpParameter
      bSuspended and CREATE_SUSPENDED or 0, # dwCreationFlags
      POINTER(uThreadId), # lpThreadId
    );
    assert hThread, \
        "CreateRemoteThread(0x%08X, NULL, 0, 0x%08X, 0, 0, ...) => Error 0x%08X" % \
        (hProcess, uAddress, KERNEL32.GetLastError());
    assert KERNEL32.CloseHandle(hThread), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hThread, KERNEL32.GetLastError());
    return uThreadId.value;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
