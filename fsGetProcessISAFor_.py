from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetOSISA import fsGetOSISA;

def fsGetProcessISAForId(uProcessId):
  hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, uProcessId);
  assert hProcess, \
      "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
  try:
    return fsGetProcessISAForHandle(hProcess);
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());

def fsGetProcessISAForHandle(hProcess):
  if fsGetOSISA() == "x86":
    return "x86";
  bIsWow64Process = BOOL();
  assert KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)), \
        "KERNEL32.IsWow64Process(%d/0x%X, ...): 0x%X" % \
        (uProcessId, uProcessId, uErrorCode);
  return bIsWow64Process and "x86" or "x64";

