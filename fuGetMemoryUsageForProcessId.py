from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fuGetMemoryUsageForProcessId(uProcessId):
  # Try to open the process...
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
  bSuccess = False;
  try:
    oProcessMemoryCounters = PROCESS_MEMORY_COUNTERS_EX();
    if not KERNEL32.K32GetProcessMemoryInfo(
      hProcess,
      fxCast(PPROCESS_MEMORY_COUNTERS, POINTER(oProcessMemoryCounters)),
      fuSizeOf(oProcessMemoryCounters)
    ):
      fThrowLastError("GetProcessMemoryInfo(0x%08X, 0x%X, 0x%X)" % \
          (hProcess.value, fuAddressOf(oProcessMemoryCounters), fuSizeOf(oProcessMemoryCounters)));
    uMemoryUsage = oProcessMemoryCounters.PrivateUsage;
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess.value) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return uMemoryUsage;