from mWindowsAPI import *;

gsOSISA = None;

def fsGetOSISA():
  global gsOSISA;
  if gsOSISA is None:
    oSystemInfo = SYSTEM_INFO();
    KERNEL32.GetNativeSystemInfo(POINTER(oSystemInfo));
    assert oSystemInfo.wProcessorArchitecture in [PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL], \
        "Unknown processor architecture %d/0x%X" % (oSystemInfo.wProcessorArchitecture, oSystemInfo.wProcessorArchitecture);
    gsOSISA = oSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL and "x86" or "x64";
  return gsOSISA;