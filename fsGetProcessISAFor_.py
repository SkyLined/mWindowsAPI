from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .oSystemInfo import oSystemInfo;
from .fThrowError import fThrowError;

def fsGetProcessISAForId(uProcessId):
  uFlags = PROCESS_QUERY_LIMITED_INFORMATION;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  hProcess \
      or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
  try:
    return fsGetProcessISAForHandle(hProcess);
  finally:
    KERNEL32.CloseHandle(hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));

def fsGetProcessISAForHandle(hProcess):
  if oSystemInfo.sOSISA == "x86":
    return "x86";
  bIsWow64Process = BOOL();
  KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)) \
        or fThrowError("IsWow64Process(%d/0x%X, ...)" % (uProcessId, uProcessId,));
  return bIsWow64Process and "x86" or "x64";

