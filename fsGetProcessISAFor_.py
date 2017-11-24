from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetOSISA import fsGetOSISA;
from fsGetErrorMessage import fsGetErrorMessage;

def fsGetProcessISAForId(uProcessId):
  uFlags = PROCESS_QUERY_LIMITED_INFORMATION;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  assert hProcess, \
      fsGetErrorMessage("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
  try:
    return fsGetProcessISAForHandle(hProcess);
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess,));

def fsGetProcessISAForHandle(hProcess):
  if fsGetOSISA() == "x86":
    return "x86";
  bIsWow64Process = BOOL();
  assert KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)), \
        fsGetErrorMessage("IsWow64Process(%d/0x%X, ...)" % (uProcessId, uProcessId,));
  return bIsWow64Process and "x86" or "x64";

