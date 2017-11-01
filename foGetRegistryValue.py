import _winreg;
from cNamedRegistryValue import cNamedRegistryValue;

gduHive_by_sName = {
  "HKCR": _winreg.HKEY_CLASSES_ROOT,
  "HKEY_CLASSES_ROOT": _winreg.HKEY_CLASSES_ROOT,
  "HKCU": _winreg.HKEY_CURRENT_USER,
  "HKEY_CURRENT_USER": _winreg.HKEY_CURRENT_USER,
  "HKLM": _winreg.HKEY_LOCAL_MACHINE,
  "HKEY_LOCAL_MACHINE": _winreg.HKEY_LOCAL_MACHINE,
  "HKU": _winreg.HKEY_USERS,
  "HKEY_USERS": _winreg.HKEY_USERS,
  "HKCC": _winreg.HKEY_CURRENT_CONFIG,
  "HKEY_CURRENT_CONFIG": _winreg.HKEY_CURRENT_CONFIG,
};

def foGetRegistryValue(sHiveName, sKeyName, sValueName = None):
  uHive = gduHive_by_sName.get(sHiveName);
  assert uHive is not None, \
      "Unknown hive %s" % repr(sHiveName);
  oHive = _winreg.ConnectRegistry(None, uHive);
  try:
    oKey = _winreg.OpenKey(oHive, sKeyName);
    xValue, uType = _winreg.QueryValueEx(oKey, sValueName);
  except WindowsError, oWindowsError:
    if oWindowsError.errno == 2:
      return None;
    raise;
  return cNamedRegistryValue(sValueName, xValue, uType = uType);
