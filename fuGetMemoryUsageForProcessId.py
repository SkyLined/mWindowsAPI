from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fuGetMemoryUsageForProcessId(uProcessId):
  # Try to open the process...
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
  bSuccess = False;
  try:
    oProcessMemoryCounters = PROCESS_MEMORY_COUNTERS_EX();
    if not oKernel32DLL.K32GetProcessMemoryInfo(
      ohProcess,
      PPROCESS_MEMORY_COUNTERS(oProcessMemoryCounters, bCast = True),
      oProcessMemoryCounters.fuGetSize()
    ):
      fThrowLastError("GetProcessMemoryInfo(%s, 0x%X, 0x%X)" % \
          (repr(ohProcess), oProcessMemoryCounters.fuGetAddress(), oProcessMemoryCounters.fuGetSize()));
    uMemoryUsage = oProcessMemoryCounters.PrivateUsage.fuGetValue();
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return uMemoryUsage;