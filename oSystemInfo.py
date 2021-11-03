from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;
from mRegistry import cRegistryValue;

def fxHKLMValue(sKeyPath, sValueName, sTypeName, bRequired = True):
  o0RegistryValue = cRegistryValue.fo0Get(sHiveName = "HKLM", sKeyPath = sKeyPath, sValueName = sValueName);
  if not o0RegistryValue:
    o0RegistryValue = cRegistryValue.fo0Get(sHiveName = "HKLM", sKeyPath = sKeyPath, sValueName = sValueName, uRegistryBits = 64);
    if not o0RegistryValue:
      assert not bRequired, \
          "Cannot read HKLM\%s\%s" % (sKeyPath, sValueName);
      return None;
  assert o0RegistryValue.sTypeName == sTypeName, \
      r"Expected HKLM\%s\%s to be %s, got %s" % (sKeyPath, sValueName, sTypeName, o0RegistryValue.sTypeName);
  return o0RegistryValue.xValue;

def fsHKLMValue(sKeyPath, sValueName, bRequired = True):
  return fxHKLMValue(sKeyPath, sValueName, "REG_SZ", bRequired);
def fuHKLMValue(sKeyPath, sValueName, bRequired = True):
  return fxHKLMValue(sKeyPath, sValueName, "REG_DWORD_LITTLE_ENDIAN", bRequired);

class cSystemInfo(object):
  def __init__(oSelf):
    oKernel32 = foLoadKernel32DLL();
    oSystemInfo = SYSTEM_INFO();
    oKernel32.GetNativeSystemInfo(oSystemInfo.foCreatePointer());
    oSelf.sOSISA = {
      PROCESSOR_ARCHITECTURE_INTEL: "x86",
      PROCESSOR_ARCHITECTURE_AMD64: "x64",
    }.get(oSystemInfo.wProcessorArchitecture.fuGetValue());
    assert oSelf.sOSISA is not None, \
        "Unknown processor architecture %s" % oSystemInfo.wProcessorArchitecture;
    oSelf.uPageSize = oSystemInfo.dwPageSize.fuGetValue();
    oSelf.uMinimumApplicationAddress = oSystemInfo.lpMinimumApplicationAddress.fuGetValue();
    oSelf.uMaximumApplicationAddress = oSystemInfo.lpMaximumApplicationAddress.fuGetValue();
    oSelf.uNumberOfProcessors = oSystemInfo.dwNumberOfProcessors.fuGetValue();
    oSelf.uAllocationAddressGranularity = oSystemInfo.dwAllocationGranularity.fuGetValue();
    
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
    return int(oSelf.sOSReleaseId);

  @property
  def sOSBuild(oSelf):
    if not oSelf.__sOSBuild:
      oSelf.__sOSBuild = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
    return oSelf.__sOSBuild;
  @property
  def uOSBuild(oSelf):
    if not oSelf.__sOSBuild:
      oSelf.__sOSBuildNumber = fsHKLMValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
    return int(oSelf.__sOSBuildNumber);
  
  @property
  def sOSPath(oSelf):
    if oSelf.__sOSPath is None:
      oKernel32 = foLoadKernel32DLL();
      osBuffer = WCHAR[MAX_PATH]();
      ouPathSize = oKernel32.GetWindowsDirectoryW(
        osBuffer.foCreatePointer(),
        MAX_PATH
      );
      if ouPathSize == 0:
        fThrowLastError("GetWindowsDirectoryW(..., 0x%X)" % (MAX_PATH,));
      oSelf.__sPath = osBuffer.fsGetNullTerminatedString();
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