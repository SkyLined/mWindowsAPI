from mDefines import MAX_PATH, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL;
from mDLLs import KERNEL32;
from mFunctions import POINTER;
from mRegistry import cRegistryValue;
from mTypes import SYSTEM_INFO;

def fsHKLMValue(sKeyName, sValueName):
  oRegistryValue = cRegistryValue.foGet(sHiveName = "HKLM", sKeyName = sKeyName, sValueName = sValueName);
  assert oRegistryValue, \
      "Cannot read HKLM\%s\%s" % (sKeyName, sValueName);
  assert oRegistryValue.sTypeName == "REG_SZ", \
      r"Expected HKLM\%s\%s to be REG_SZ, got %s" % (sKeyName, sValueName, oRegistryValue.sType);
  return oRegistryValue.xValue;


class cSystemInfo(object):
  def __init__(oSelf):
    oSystemInfo = SYSTEM_INFO();
    KERNEL32.GetNativeSystemInfo(POINTER(oSystemInfo));
    oSelf.sOSISA = {
      PROCESSOR_ARCHITECTURE_INTEL: "x86",
      PROCESSOR_ARCHITECTURE_AMD64: "x64",
    }.get(oSystemInfo.wProcessorArchitecture);
    assert oSelf.sOSISA is not None, \
        "Unknown processor architecture 0x%X" % oSystemInfo.wProcessorArchitecture;
    oSelf.uPageSize = oSystemInfo.dwPageSize;
    oSelf.uMinimumApplicationAddress = oSystemInfo.lpMinimumApplicationAddress;
    oSelf.uMaximumApplicationAddress = oSystemInfo.lpMaximumApplicationAddress;
    oSelf.uNumberOfProcessors = oSystemInfo.dwNumberOfProcessors;
    oSelf.uAllocationAddressGranularity = oSystemInfo.dwAllocationGranularity;
    
    oSelf.__sOSName = None;
    oSelf.__sOSReleaseId = None;
    oSelf.__sOSBuild = None;
    oSelf.__sOSPath = None;
    oSelf.__sUniqueMachineId = None;
  
  @property
  def sOSName(oSelf):
    if not oSelf.__sOSName:
      oSelf.__sOSName = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
    return oSelf.__sOSName;

  @property
  def sReleaseId(oSelf):
    if not oSelf.__sReleaseId:
      oSelf.__sReleaseId = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId");
    return oSelf.__sReleaseId;
  @property
  def uReleaseId(oSelf):
    return long(oSelf.sReleaseId);

  @property
  def sOSBuild(oSelf):
    if not oSelf.__sOSBuild:
      oSelf.__sOSBuild = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
    return oSelf.__sOSBuild;
  @property
  def uOSBuild(oSelf):
    return long(oSelf.sOSBuild);
  
  @property
  def sOSPath(oSelf):
    if oSelf.__sOSPath is None:
      sBuffer = WSTR(MAX_PATH);
      uPathSize = KERNEL32.GetWindowsDirectoryW(sBuffer, MAX_PATH);
      uPathSize > 0 \
          or fThrowError("GetWindowsDirectoryW(..., 0x%X)" % (MAX_PATH,));
      oSelf.__sPath = sBuffer.value;
    return oSelf.__sPath;
  
  def sUniqueMachineId(oSelf):
    if not oSelf.__sUniqueMachineId:
      oSelf.__sUniqueMachineId = fsHKLMValue(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid");
    return oSelf.__sUniqueMachineId;
  
  @property
  def sOSVersion(oSelf):
    return "%s release %s, build %s %s in %s" % \
        (oSelf.sOSName, oSelf.sReleaseId, oSelf.sCurrentBuild, oSelf.sISA, oSelf.sPath);

oSystemInfo = cSystemInfo();