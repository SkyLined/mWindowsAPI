import _winreg;

gduType_by_sName = {
  "REG_BINARY":                     _winreg.REG_BINARY,
  "REG_DWORD":                      _winreg.REG_DWORD,
  "REG_DWORD_LITTLE_ENDIAN":        _winreg.REG_DWORD_LITTLE_ENDIAN,
  "REG_DWORD_BIG_ENDIAN":           _winreg.REG_DWORD_BIG_ENDIAN,
  "REG_EXPAND_SZ":                  _winreg.REG_EXPAND_SZ,
  "REG_LINK":                       _winreg.REG_LINK,
  "REG_MULTI_SZ":                   _winreg.REG_MULTI_SZ,
  "REG_NONE":                       _winreg.REG_NONE,
  "REG_RESOURCE_LIST":              _winreg.REG_RESOURCE_LIST,
  "REG_FULL_RESOURCE_DESCRIPTOR":   _winreg.REG_FULL_RESOURCE_DESCRIPTOR,
  "REG_RESOURCE_REQUIREMENTS_LIST": _winreg.REG_RESOURCE_REQUIREMENTS_LIST,
  "REG_SZ":                         _winreg.REG_SZ,
};
gdsName_by_uType = dict([(u, s) for (s, u) in gduType_by_sName.items()]);

class cNamedRegistryValue(object):
  def __init__(oNamedValue, sName, xValue, uType = None, sType = None):
    if uType is None:
      assert sType is not None, \
          "uType or sType must be specified";
      assert sType in gduType_by_sName, \
          "Unknown sType: %s" % repr(sType);
      uType = gduType_by_sName[sType];
    elif sType is None:
      assert uType in gdsName_by_uType, \
          "Unknown uType: %s" % repr(uType);
      sType = gdsName_by_uType[uType];
    else:
      assert sType == gdsName_by_uType[uType], \
          "uType and sType mismatch: %s/%s" % (rpr(uType), repr(sType));
    oNamedValue.sName = sName;
    oNamedValue.xValue = xValue;
    oNamedValue.uType = uType;
    oNamedValue.sType = sType;
