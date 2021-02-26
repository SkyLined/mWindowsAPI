from mWindowsSDK import *;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fuGetMemoryUsageForProcessId(uProcessId):
  # Try to open the process...
  oKernel32 = foLoadKernel32DLL();
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
  bSuccess = False;
  try:
    oProcessMemoryCounters = PROCESS_MEMORY_COUNTERS_EX();
    if not oKernel32.K32GetProcessMemoryInfo(
      ohProcess,
      oProcessMemoryCounters.foCreatePointer(PPROCESS_MEMORY_COUNTERS),
      oProcessMemoryCounters.fuGetSize()
    ):
      fThrowLastError("GetProcessMemoryInfo(%s, 0x%X, 0x%X)" % \
          (repr(ohProcess), oProcessMemoryCounters.fuGetAddress(), oProcessMemoryCounters.fuGetSize()));
    uMemoryUsage = oProcessMemoryCounters.PrivateUsage.fuGetValue();
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uMemoryUsage;