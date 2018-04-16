import _winreg;

# There are more imports at the end that need to be there and not here to prevent import loops.

gduType_by_sName = {
  "REG_BINARY":                       _winreg.REG_BINARY,
  "REG_DWORD":                        _winreg.REG_DWORD,
  "REG_DWORD_LITTLE_ENDIAN":          _winreg.REG_DWORD_LITTLE_ENDIAN,
  "REG_DWORD_BIG_ENDIAN":             _winreg.REG_DWORD_BIG_ENDIAN,
  "REG_EXPAND_SZ":                    _winreg.REG_EXPAND_SZ,
  "REG_LINK":                         _winreg.REG_LINK,
  "REG_MULTI_SZ":                     _winreg.REG_MULTI_SZ,
  "REG_NONE":                         _winreg.REG_NONE,
  "REG_RESOURCE_LIST":                _winreg.REG_RESOURCE_LIST,
  "REG_FULL_RESOURCE_DESCRIPTOR":     _winreg.REG_FULL_RESOURCE_DESCRIPTOR,
  "REG_RESOURCE_REQUIREMENTS_LIST":   _winreg.REG_RESOURCE_REQUIREMENTS_LIST,
  "REG_SZ":                           _winreg.REG_SZ,
};
gdsName_by_uType = dict([(u, s) for (s, u) in gduType_by_sName.items()]);
# Also add names without "REG_" prefix:
gduType_by_sName.update(dict([(s[4:], u) for (s, u) in gduType_by_sName.items()]));

class cRegistryValue(object):
  duType_by_sName = gduType_by_sName;
  dsName_by_uType = gdsName_by_uType;
  
  @staticmethod
  def foSet(uType = None, sTypeName = None, xValue = None, **dxRegistryHiveKeyNamedValueArguments):
    oRegistryValue = cRegistryValue(uType = uType, sTypeName = sTypeName, xValue = xValue);
    oRegistryHiveKeyNamedValue = cRegistryHiveKeyNamedValue(**dxRegistryHiveKeyNamedValueArguments);
    return oRegistryHiveKeyNamedValue.foSet(oRegistryValue);
  
  @staticmethod
  def foGet(**dxRegistryHiveKeyNamedValueArguments):
    oRegistryHiveKeyNamedValue = cRegistryHiveKeyNamedValue(**dxRegistryHiveKeyNamedValueArguments);
    return oRegistryHiveKeyNamedValue.foGet();
  
  def __init__(oSelf, xUnused = None, uType = None, sTypeName = None, xValue = None):
    assert xUnused is None, \
        "Constructor arguments must be named values!";
    if uType is None:
      assert sTypeName is not None, \
          "You must provide a value for either uType or sTypeName";
      uType = cRegistryValue.duType_by_sName.get(sTypeName);
      assert uType is not None, \
          "You must provide a valid value for sTypeName, not %s" % repr(sTypeName);
    else:
      assert sTypeName is None, \
          "You must provide a value for either uType or sTypeName, not both";
    
    oSelf.uType = uType;
    oSelf.xValue = xValue;
  
  @property
  def uType(oSelf):
    return oSelf.__uType;
  @uType.setter
  def uType(oSelf, uType):
    assert uType in cRegistryValue.dsName_by_uType, \
        "You must specify a valid value for uType, not %s" % repr(uType);
    oSelf.__uType = uType;
  @property
  def sTypeName(oSelf):
    return cRegistryValue.dsName_by_uType[oSelf.__uType];
  @sTypeName.setter
  def sTypeName(oSelf, sTypeName):
    uType = cRegistryValue.duType_by_sName.get(sTypeName);
    assert uType, \
        "You must specify a valid value for sTypeName, not %s" % repr(sTypeName);
    oSelf.__uType = uType;
  
  def __eq__(oSelf, oRegistryValue):
    if oRegistryValue.__class__ != cRegistryValue or oSelf.uType != oRegistryValue.uType:
      return NotImplemented;
    return oSelf.xValue == oRegistryValue.xValue;
  def __ge__(oSelf, oRegistryValue):
    if oRegistryValue.__class__ != cRegistryValue or oSelf.uType != oRegistryValue.uType:
      return NotImplemented;
    return oSelf.xValue >= oRegistryValue.xValue;
  def __gt__(oSelf, oRegistryValue):
    if oRegistryValue.__class__ != cRegistryValue or oSelf.uType != oRegistryValue.uType:
      return NotImplemented;
    return oSelf.xValue > oRegistryValue.xValue;
  def __le__(oSelf, oRegistryValue):
    return not oSelf.__gt__(oRegistryValue);
  def __lt__(oSelf, oRegistryValue):
    return not oSelf.__ge__(oRegistryValue);
  def __ne__(oSelf, oRegistryValue):
    return not oSelf.__eq__(oRegistryValue);
  
from .cRegistryHiveKeyNamedValue import cRegistryHiveKeyNamedValue;
