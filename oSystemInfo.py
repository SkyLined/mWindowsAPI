from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;

class cSystemInfo(object):
  def __init__(oSelf):
    oSystemInfo = SYSTEM_INFO();
    KERNEL32.GetNativeSystemInfo(POINTER(oSystemInfo));
    assert oSystemInfo.wProcessorArchitecture in [PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL], \
        "Unknown processor architecture %d/0x%X" % (oSystemInfo.wProcessorArchitecture, oSystemInfo.wProcessorArchitecture);
    oSelf.sOSISA = oSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL and "x86" or "x64";
    oSelf.uPageSize = oSystemInfo.dwPageSize;
    oSelf.uMinimumApplicationAddress = oSystemInfo.lpMinimumApplicationAddress;
    oSelf.uMaximumApplicationAddress = oSystemInfo.lpMaximumApplicationAddress;
    oSelf.uNumberOfProcessors = oSystemInfo.dwNumberOfProcessors;
    oSelf.uAllocationAddressGranularity = oSystemInfo.dwAllocationGranularity;

oSystemInfo = cSystemInfo();