# There are imports at the end that need to be there and not here to prevent import loops.

class cRegistryHiveKeyNamedValue(object):
  def __init__(oSelf, xUnused = None, sValueName = None, oRegistryHiveKey = None, **dxRegistryHiveKeyArguments):
    assert xUnused is None, \
        "Constructor arguments must be named values!";
    assert sValueName is not None, \
        "You must provide a valid value for sValueName, not %s" % repr(sValueName);
    if oRegistryHiveKey is None:
      oRegistryHiveKey = cRegistryHiveKey(**dxRegistryHiveKeyArguments);
    else:
      assert not dxRegistryHiveKeyArguments, \
          "You must provide either oRegistryHiveKey or dxRegistryHiveKeyArguments, not both";
    oSelf.sValueName = sValueName;
    oSelf.__oRegistryHiveKey = oRegistryHiveKey;
    
  # Getter/setter for oRegistryHive
  @property
  def oRegistryHive(oSelf):
    return oSelf.__oRegistryHiveKey.oRegistryHive;
  @oRegistryHive.setter
  def oRegistryHive(oSelf, oRegistryHive):
    oSelf.__oRegistryHiveKey.oRegistryHive = oRegistryHive;
  # Getter/setter for oRegistryHiveKey
  @property
  def oRegistryHiveKey(oSelf):
    return oSelf.__oRegistryHiveKey;
  @oRegistryHiveKey.setter
  def oRegistryHiveKey(oSelf, oRegistryHiveKey):
    oSelf.__oRegistryHiveKey = oRegistryHiveKey;
  
  # Getter/setter for oRegistryValue
  def foGet(oSelf):
    return oSelf.__oRegistryHiveKey.foGetNamedValue(oSelf.sValueName);
  def foSet(oSelf, oRegistryValue):
    return oSelf.__oRegistryHiveKey.foSetNamedValue(oSelf.sValueName, oRegistryValue);
  def fbDelete(oSelf):
    return oSelf.__oRegistryHiveKey.fbDeleteNamedValue(oSelf.sValueName);
  
  @property
  def sFullPath(oSelf):
    return "%s\\%s" % (oSelf.__oRegistryHiveKey.sFullPath, oSelf.sValueName);

from .cRegistryHiveKey import cRegistryHiveKey;
from .cRegistryValue import cRegistryValue;
