from mDefines import FALSE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ;
from mFunctions import CAST, HRESULT_FROM_WIN32, POINTER, SIZEOF;
from mTypes import PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX;
from mDLLs import KERNEL32;

def fuGetProcessMemoryUsage(uProcessId):
  # Try to open the process...
  hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, uProcessId);
  assert hProcess, \
      "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, 0x%08X) => Win32 Error 0x%X / HRESULT 0x%08X" % \
      (uProcessId, KERNEL32.GetLastError(), HRESULT_FROM_WIN32(KERNEL32.GetLastError()));
  try:
    oProcessMemoryCounters = PROCESS_MEMORY_COUNTERS_EX();
    poProcessMemoryCounters = CAST(POINTER(PROCESS_MEMORY_COUNTERS), POINTER(oProcessMemoryCounters));
    assert KERNEL32.K32GetProcessMemoryInfo(
      hProcess,
      poProcessMemoryCounters,
      SIZEOF(oProcessMemoryCounters)
    ), "GetProcessMemoryInfo(0x%08X, ..., 0x%X) => Win32 Error 0x%X / HRESULT 0x%08X" % \
        (hProcess.value, SIZEOF(oProcessMemoryCounters), \
        KERNEL32.GetLastError(), HRESULT_FROM_WIN32(KERNEL32.GetLastError()));
    return oProcessMemoryCounters.PrivateUsage;
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Win32 Error 0x%X / HRESULT 0x%08X" % \
        (hProcess.value, KERNEL32.GetLastError(), HRESULT_FROM_WIN32(KERNEL32.GetLastError()));
