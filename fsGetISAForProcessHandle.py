from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;
from .oSystemInfo import oSystemInfo;

if oSystemInfo.sOSISA == "x86":
  def fsGetISAForProcessHandle(hProcess):
    return "x86"; # Not other option
else:
  def fsGetISAForProcessHandle(hProcess):
    bIsWow64Process = BOOL();
    if not KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)):
      fThrowLastError("IsWow64Process(0x%X, ...)" % (hProcess.value,));
    return bIsWow64Process and "x86" or "x64";

