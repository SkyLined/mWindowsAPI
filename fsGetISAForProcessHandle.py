from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowLastError import fThrowLastError;
from .oSystemInfo import oSystemInfo;

if oSystemInfo.sOSISA == "x86":
  def fsGetISAForProcessHandle(ohProcess):
    return "x86"; # Not other option
else:
  def fsGetISAForProcessHandle(ohProcess):
    obIsWow64Process = BOOL();
    opobIsWow64Process = obIsWow64Process.foCreatePointer()
    if not oKernel32DLL.IsWow64Process(ohProcess, opobIsWow64Process):
      fThrowLastError("IsWow64Process(%s, %s)" % (repr(ohProcess), repr(opobIsWow64Process)));
    return "x86" if obIsWow64Process.fbGetValue() else "x64";

