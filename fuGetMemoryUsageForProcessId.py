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
      fThrowLastError("GetProcessMemoryInfo(0x%08X, 0x%X, 0x%X)" % \
          (ohProcess.value, oProcessMemoryCounters.fuGetAddress(), oProcessMemoryCounters.fuGetSize()));
    uMemoryUsage = oProcessMemoryCounters.PrivateUsage.value;
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess.value) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return uMemoryUsage;