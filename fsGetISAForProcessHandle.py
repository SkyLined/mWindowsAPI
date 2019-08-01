from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fThrowLastError import fThrowLastError;
from .oSystemInfo import oSystemInfo;

if oSystemInfo.sOSISA == "x86":
  def fsGetISAForProcessHandle(ohProcess):
    return "x86"; # Not other option
else:
  def fsGetISAForProcessHandle(ohProcess):
    obIsWow64Process = BOOLEAN();
    if not oKernel32.IsWow64Process(ohProcess, obIsWow64Process.foCreatePointer()):
      fThrowLastError("IsWow64Process(0x%X, ...)" % (ohProcess.value,));
    return "x64" if obIsWow64Process.value == 0 else "x86";

