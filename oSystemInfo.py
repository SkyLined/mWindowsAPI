from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mRegistry import cRegistryValue;
from .mTypes import *;

def fxHKLMValue(sKeyName, sValueName, sTypeName, bRequired = True):
  oRegistryValue = cRegistryValue.foGet(sHiveName = "HKLM", sKeyName = sKeyName, sValueName = sValueName);
  if not oRegistryValue:
    oRegistryValue = cRegistryValue.foGet(sHiveName = "HKLM", sKeyName = sKeyName, sValueName = sValueName, uRegistryBits = 64);
    if not oRegistryValue:
      assert not bRequired, \
          "Cannot read HKLM\%s\%s" % (sKeyName, sValueName);
      return None;
  assert oRegistryValue.sTypeName == sTypeName, \
      r"Expected HKLM\%s\%s to be %s, got %s" % (sKeyName, sValueName, sTypeName, oRegistryValue.sTypeName);
  return oRegistryValue.xValue;

def fsHKLMValue(sKeyName, sValueName, bRequired = True):
  return fxHKLMValue(sKeyName, sValueName, "REG_SZ", bRequired);
def fuHKLMValue(sKeyName, sValueName, bRequired = True):
  return fxHKLMValue(sKeyName, sValueName, "REG_DWORD", bRequired);

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
    oSelf.__uOSMajorVersionNumber = None;
    oSelf.__uOSMinorVersionNumber = None;
    oSelf.__sOSVersion = None;
    oSelf.__sOSReleaseId = None;
    oSelf.__sOSBuild = None;
    oSelf.__sOSPath = None;
    oSelf.__sSystemName = None;
    oSelf.__sUniqueSystemId = None;
  
  @property
  def sOSName(oSelf):
    if not oSelf.__sOSName:
      oSelf.__sOSName = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
      sServicePackName = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CSDVersion", bRequired = False);
      if sServicePackName:
        oSelf.__sOSName += " " + sServicePackName;
    return oSelf.__sOSName;
  
  @property
  def sOSVersion(oSelf):
    if oSelf.__uOSMajorVersionNumber is None:
      oSelf.__uOSMajorVersionNumber = fuHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMajorVersionNumber", bRequired = False);
    if oSelf.__uOSMajorVersionNumber is not None and oSelf.__uOSMinorVersionNumber is None:
      oSelf.__uOSMinorVersionNumber = fuHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMinorVersionNumber", bRequired = False);
    if oSelf.__uOSMajorVersionNumber is None or oSelf.__uOSMinorVersionNumber is None:
      if not oSelf.__sOSVersion:
        oSelf.__sOSVersion = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentVersion");
      return oSelf.__sOSVersion;
    return "%d.%d" % (oSelf.__uOSMajorVersionNumber, oSelf.__uOSMinorVersionNumber);
  
  @property
  def sOSReleaseId(oSelf):
    if not oSelf.__sOSReleaseId:
      oSelf.__sOSReleaseId = (
        # Windows 10
        fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", bRequired = False) \
        # Windows 7
        or fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CSDBuildNumber")
      );
    return oSelf.__sOSReleaseId;
  @property
  def uReleaseId(oSelf):
    return long(oSelf.sOSReleaseId);

  @property
  def sOSBuild(oSelf):
    if not oSelf.__sOSBuild:
      oSelf.__sOSBuild = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
    return oSelf.__sOSBuild;
  @property
  def uOSBuild(oSelf):
    if not oSelf.__sOSBuild:
      oSelf.__sOSBuildNumber = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
    return long(oSelf.__sOSBuildNumber);
  
  @property
  def sOSPath(oSelf):
    if oSelf.__sOSPath is None:
      sBuffer = WSTR(MAX_PATH);
      oPathSize = KERNEL32.GetWindowsDirectoryW(sBuffer, MAX_PATH);
      if oPathSize.value == 0:
        fThrowLastError("GetWindowsDirectoryW(..., 0x%X)" % (MAX_PATH,));
      oSelf.__sPath = sBuffer.value;
    return oSelf.__sPath;
  
  @property
  def sSystemName(oSelf):
    if not oSelf.__sSystemName:
      oSelf.__sSystemName = fsHKLMValue(r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName");
    return oSelf.__sSystemName;
  
  @property
  def sUniqueSystemId(oSelf):
    if not oSelf.__sUniqueSystemId:
      oSelf.__sUniqueSystemId = fsHKLMValue(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid");
    return oSelf.__sUniqueSystemId;
  
  @property
  def sOSFullDetails(oSelf):
    return "%s (version %s, release %s, build %s %s) in %s" % \
        (oSelf.sOSName, oSelf.sOSVersion, oSelf.sOSReleaseId, oSelf.sOSBuild, oSelf.sOSISA, oSelf.sOSPath);

oSystemInfo = cSystemInfo();