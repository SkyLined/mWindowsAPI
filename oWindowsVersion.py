from foGetRegistryValue import foGetRegistryValue;
from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from oSystemInfo import oSystemInfo;

def fsReadRegistryValue(sValueName):
  oRegistryValue = foGetRegistryValue("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", sValueName);
  assert oRegistryValue, \
      "Cannot read HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\%s" % sValueName;
  assert oRegistryValue.sType == "REG_SZ", \
      r"Expected HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\%s to be REG_SZ, got %s" % (sValueName, oRegistryValue.sType);
  return oRegistryValue.xValue;

class cWindowsVersion(object):
  def __init__(oSelf):
    oSelf.__sProductName = None;
    oSelf.__sReleaseId = None;
    oSelf.__sCurrentBuild = None;
    oSelf.__sISA = None;
    oSelf.__sPath = None;
  
  @property
  def sProductName(oSelf):
    if not oSelf.__sProductName:
      oSelf.__sProductName = fsReadRegistryValue("ProductName");
    return oSelf.__sProductName;

  @property
  def sReleaseId(oSelf):
    if not oSelf.__sReleaseId:
      oSelf.__sReleaseId = fsReadRegistryValue("ReleaseId");
    return oSelf.__sReleaseId;
  @property
  def uReleaseId(oSelf):
    return long(oSelf.sReleaseId);

  @property
  def sCurrentBuild(oSelf):
    if not oSelf.__sCurrentBuild:
      oSelf.__sCurrentBuild = fsReadRegistryValue("CurrentBuild");
    return oSelf.__sCurrentBuild;
  @property
  def uCurrentBuild(oSelf):
    return long(oSelf.sCurrentBuild);
  
  @property
  def sISA(oSelf):
    return oSystemInfo.sOSISA;
  
  @property
  def sPath(oSelf):
    if oSelf.__sPath is None:
      sBuffer = WSTR(MAX_PATH);
      uPathSize = KERNEL32.GetWindowsDirectoryW(sBuffer, MAX_PATH);
      uPathSize > 0 \
          or fThrowError("GetWindowsDirectoryW(..., 0x%X)" % (MAX_PATH,));
      oSelf.__sPath = sBuffer.value;
    return oSelf.__sPath;
  
  def __str__(oSelf):
    return "%s release %s, build %s %s in %s" % \
        (oSelf.sProductName, oSelf.sReleaseId, oSelf.sCurrentBuild, oSelf.sISA, oSelf.sPath);

oWindowsVersion = cWindowsVersion();
