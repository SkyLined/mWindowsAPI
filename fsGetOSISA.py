from mWindowsAPI import *;

goSystemInfo = None;

def fsGetOSISA():
  global goSystemInfo;
  if goSystemInfo is None:
    goSystemInfo = SYSTEM_INFO();
    KERNEL32.GetNativeSystemInfo(POINTER(goSystemInfo));
    assert goSystemInfo.wProcessorArchitecture in [PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL], \
        "Unknown processor architecture %d/0x%X" % (goSystemInfo.wProcessorArchitecture, goSystemInfo.wProcessorArchitecture);
  return goSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL and "x86" or "x64";
