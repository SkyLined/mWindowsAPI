import _winreg;

from ..mDefines import ERROR_FILE_NOT_FOUND;
from ..mFunctions import WIN32_FROM_HRESULT;
# There are more imports at the end that need to be there and not here to prevent import loops.

class cRegistryHiveKey(object):
  def __init__(oSelf, xUnused = None, sKeyName = None, oRegistryHive = None, oWinRegKey = None, bWinRegKeyOpenForWriting = False, uRegistryBits = 0, **dxRegistryHiveArguments):
    assert xUnused is None, \
        "Constructor arguments must be named values!";
    assert sKeyName is not None, \
        "You must provide a valid value for sKeyName, not %s" % repr(sKeyName);
    if oRegistryHive is None:
      oRegistryHive = cRegistryHive(**dxRegistryHiveArguments);
    else:
      assert not dxRegistryHiveArguments, \
          "You must provide either oRegistryHive or dxRegistryHiveArguments, not both";
    
    oSelf.__oRegistryHive = oRegistryHive;
    oSelf.__sKeyName = sKeyName;
    oSelf.__oWinRegKey = oWinRegKey;
    oSelf.__bKeyOpenForWriting = bWinRegKeyOpenForWriting;
    oSelf.__uRegistryBits = uRegistryBits;
  
  @property
  def oRegistryHive(oSelf):
    # Getter for oRegistryHive
    return oSelf.__oRegistryHive;
  @oRegistryHive.setter
  def oRegistryHive(oSelf, oRegistryHive):
    # Setter for oRegistryHive deletes cached oWinRegKey
    oSelf.__oWinRegKey = None;
    oSelf.__oRegistryHive = oRegistryHive;
  
  @property
  def sKeyName(oSelf):
    # Getter for sKeyName
    return oSelf.__sKeyName;
  @sKeyName.setter
  def sKeyName(oSelf, sKeyName):
    # Setter for sKeyName deletes cached oWinRegKey
    oSelf.__oWinRegKey = None;
    oSelf.__sKeyName = sKeyName;
  def __foOpenWinRegKey(oSelf, bForWriting = False):
    # return cached oWinRegKey if appropriate or create a new oWinRegKey
    if (bForWriting and not oSelf.__bKeyOpenForWriting):
      oSelf.__oWinRegKey = None;
    if oSelf.__oWinRegKey is None:
      oSelf.__oWinRegKey = oSelf.__oRegistryHive.foOpenWinRegKey(oSelf.sKeyName, bForWriting = bForWriting, uRegistryBits = oSelf.__uRegistryBits);
      oSelf.__bKeyOpenForWriting = bForWriting;
    return oSelf.__oWinRegKey;

  def __foCreateWinRegKey(oSelf, bForWriting = False):
    # return cached oWinRegKey if appropriate or create a new oWinRegKey
    if (bForWriting and not oSelf.__bKeyOpenForWriting):
      oSelf.__oWinRegKey = None;
    if oSelf.__oWinRegKey is None:
      oSelf.__oWinRegKey = oSelf.__oRegistryHive.foCreateWinRegKey(oSelf.sKeyName, bForWriting = bForWriting, uRegistryBits = oSelf.__uRegistryBits);
      oSelf.__bKeyOpenForWriting = bForWriting;
    return oSelf.__oWinRegKey;
  
  @property
  def bExists(oSelf):
    return oSelf.__foOpenWinRegKey() is not None;

  def fbCreate(oSelf, bForWriting = False):
    if oSelf.bExists:
      return True;
    oSelf.__oWinRegKey = oSelf.__oRegistryHive.foCreateWinRegKey(oSelf.sKeyName, bForWriting = bForWriting, uRegistryBits = oSelf.__uRegistryBits);
    bSuccess = oSelf.__oWinRegKey is not None;
    oSelf.__bKeyOpenForWriting = bSuccess and bForWriting;
    return bSuccess;
  
  def fbDelete(oSelf):
    for sName in oSelf.doSubKey_by_sName.keys():
      if not oSelf.fbDeleteSubKey(sSubKeyName):
        return False;
    return oSelf.oParentHiveKey.fbDeleteSubKey(oSelf.sKeyName);
  
  def fbDeleteSubKey(oSelf, sSubKeyName):
    return oSelf.__oRegistryHive.fbDeleteHiveKeySubKey(oSelf, sSubKeyName, uRegistryBits = oSelf.__uRegistryBits);
  
  @property
  def oParentHiveKey(oSelf):
    try:
      sParentKeyName = oSelf.sKeyName[:oSelf.sKeyName.rindex("\\")];
    except ValueError:
      return None; # This is a root key; there is no parent
    return cRegistryHiveKey(sKeyName = sParentKeyName, oRegistryHive = oSelf.__oRegistryHive, uRegistryBits = oSelf.__uRegistryBits);
  
  def foCreateSubKey(oSelf, sSubKeyName, bForWriting = False):
    return oSelf.__oRegistryHive.foCreateHiveKey(r"%s\%s" % (oSelf.sKeyName, sSubKeyName), bForWriting = bForWriting, uRegistryBits = oSelf.__uRegistryBits);
  
  def foGetSubKey(oSelf, sSubKeyName):
    return cRegistryHiveKey(
      sKeyName = r"%s\%s" % (oSelf.sKeyName, sSubKeyName),
      oRegistryHive = oSelf.__oRegistryHive,
    );
  
  @property
  def aoSubKeys(oSelf):
    doSubKey_by_sName = oSelf.doSubKey_by_sName();
    if doSubKey_by_sName is None:
      return None;
    return doSubKey_by_sName.values();

  @property
  def doSubKey_by_sName(oSelf):
    oWinRegKey = oSelf.__foOpenWinRegKey();
    if not oWinRegKey:
      return None;
    doSubKey_by_sName = {};
    while 1:
      try:
        sSubKeyName = _winreg.EnumKey(oWinRegKey, len(doSubKey_by_sName));
      except WindowsError:
        return doSubKey_by_sName;
      doSubKey_by_sName[sSubKeyName] = cRegistryHiveKey(
        sKeyName = "%s\%s" % (oSelf.sKeyName, sSubKeyName),
        oRegistryHive = oSelf.__oRegistryHive,
      );
  
  @property
  def aoNamedValues(oSelf):
    oWinRegKey = oSelf.__foOpenWinRegKey();
    if not oWinRegKey:
      return None;
    aoNamedValues = [];
    while 1:
      try:
        (sValueName, xValue, uValueType) = _winreg.EnumValue(oWinRegKey, len(aoSubKeys));
      except WindowsError:
        return aoNamedValues;
      aoNamedValues.append(cRegistryHiveKeyNamedValue(sValueName = oSelf.sValueName, oRegistryHiveKey = oSelf));
  
  @property
  def doValue_by_Name(oSelf):
    oWinRegKey = oSelf.__foOpenWinRegKey();
    if not oWinRegKey:
      return None;
    doValue_by_Name = {};
    while 1:
      try:
        (sValueName, xValue, uType) = _winreg_EnumValue(oWinRegKey, len(aoSubKeys));
      except WindowsError:
        return aoNamedValues;
      doValue_by_Name[sValueName] = cRegistryValue(uType = uType, xValue = xValue);
  
  def foCreateNamedValue(oSelf, sValueName):
    return cRegistryHiveKeyNamedValue(sValueName = sValueName, oRegistryHiveKey = oSelf);
  
  def foGetNamedValue(oSelf, sValueName):
    oWinRegKey = oSelf.__foOpenWinRegKey();
    if not oWinRegKey:
      return None;
    try:
      xValue, uType = _winreg.QueryValueEx(oWinRegKey, sValueName);
    except WindowsError, oWindowsError:
      if oWindowsError.errno == WIN32_FROM_HRESULT(ERROR_FILE_NOT_FOUND):
        # The value does not exist.
        return None;
      raise;
    return cRegistryValue(uType = uType, xValue = xValue);

  def foSetNamedValue(oSelf, sValueName, oRegistryValue = None, **dxRegistryValueArguments):
    if oRegistryValue is None:
      assert dxRegistryValueArguments, \
          "You must provide a value for either oRegistryValue or dxRegistryValueArguments";
      oRegistryValue = cRegistryValue(**dxRegistryValueArguments);
    oWinRegKey = oSelf.__foCreateWinRegKey(bForWriting = True);
    if not oWinRegKey:
      return None;
    _winreg.SetValueEx(oWinRegKey, sValueName, 0, oRegistryValue.uType, oRegistryValue.xValue);
    return oRegistryValue;
  
  def fbDeleteNamedValue(oSelf, sValueName):
    if not oSelf.bExists:
      return True; # The key does not exist.
    oWinRegKey = oSelf.__foOpenWinRegKey(bForWriting = True);
    if not oWinRegKey:
      return False; # Could not open the key.
    try:
      _winreg.DeleteValue(oWinRegKey, sValueName);
    except WindowsError, oWindowsError:
      if oWindowsError.errno == WIN32_FROM_HRESULT(ERROR_FILE_NOT_FOUND):
        return True; # The value does not exist.
      raise;
    return True;
  
  @property
  def sFullPath(oSelf):
    return "%s\\%s" % (oSelf.__oRegistryHive.sFullPath, oSelf.sKeyName);
  
from .cRegistryHive import cRegistryHive;
from .cRegistryHiveKeyNamedValue import cRegistryHiveKeyNamedValue;
from .cRegistryValue import cRegistryValue;
