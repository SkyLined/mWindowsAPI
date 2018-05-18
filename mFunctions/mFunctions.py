import ctypes;
from ..fsGetPythonISA import fsGetPythonISA;

CAST = lambda cType, oInstance: ctypes.cast(oInstance, cType);
SIZEOF = ctypes.sizeof;
ADDRESSOF = ctypes.addressof;

def BUFFER(uSize):
  oBuffer = (ctypes.c_byte * uSize)();
  for uIndex in xrange(uSize):
    oBuffer[uIndex] = 0;
  return oBuffer;

def HRESULT_FROM_WIN32(uWin32):
  return 0x80070000 + uWin32;

 # ctypes lacks specific types for 32-bit and 64-bit pointers; this is a work-around:
class cPOINTER_32(ctypes.c_ulong, ctypes.c_void_p):
  def __init__(oSelf, uValue):
    super(oSelf.__class__, oSelf).__init__(uValue);
    if oSelf.value != uValue:
      raise ValueError("Cannot store 0x%X in a %s" % (uValue, oSelf.__class__.__name__));

class cPOINTER_64(ctypes.c_ulonglong, ctypes.c_void_p):
  def __init__(oSelf, uValue):
    super(oSelf.__class__, oSelf).__init__(uValue);
    if oSelf.value != uValue:
      raise ValueError("Cannot store 0x%X in a %s" % (uValue, oSelf.__class__.__name__));

def POINTER(cType_or_xInstance):
  if type(cType_or_xInstance).__class__ == type:
    # If this is a type return a pointer-to-type.
    return ctypes.POINTER(cType_or_xInstance);
  return ctypes.byref(cType_or_xInstance);

def POINTER_32(cType_or_uAddress = None):
  if cType_or_uAddress is None or type(cType_or_uAddress).__class__ == type:
    return cPOINTER_32; # Not sub-typed to the type it's pointing to :(
  assert fsGetPythonISA() == "x86", \
      "Cannot create a 32-bit pointer to an object in a 64-bit process!";
  return ctypes.byref(cType_or_uAddress);
def POINTER_64(cType_or_uAddress = None):
  if cType_or_uAddress is None or type(cType_or_uAddress).__class__ == type:
    return cPOINTER_64; # Not sub-typed to the type it's pointing to :(
  assert fsGetPythonISA() == "x64", \
      "Cannot create a 64-bit pointer to an object in a 32-bit process!";
  return ctypes.byref(cType_or_uAddress);

def POINTER_VALUE(pxInstance):
  if pxInstance.__class__ in [cPOINTER_32, cPOINTER_64, ctypes.c_void_p]:
    return pxInstance.value or None;
  try:
    return ctypes.c_void_p.from_buffer(pxInstance).value;
  except TypeError:
    raise TypeError("Cannot get the pointer value of a %s (%s)" % (type(pxInstance), repr(pxInstance)));

def POINTER_TARGET(pxInstance):
  assert not pxInstance.__class__ in [cPOINTER_32, cPOINTER_64, ctypes.c_void_p], \
      "Unfortunately, this is not implemented";
  if hasattr(pxInstance, "contents"):
    return pxInstance.contents;
  if hasattr(pxInstance, "value"):
    return pxInstance.value;
  raise TypeError("Cannot get the pointer target of a %s (%s)" % (type(pxInstance), repr(pxInstance)));

def STR(sData_or_uSize, uSize = None):
  return ctypes.create_string_buffer(sData_or_uSize, uSize);

def SUCCEEDED(uHResult):
  return uHResult < 0x80000000;

def WIN32_FROM_HRESULT(hResult):
  assert hResult & 0xFFFF0000 == 0x80070000;
  return hResult &0xFFFF;

def WSTR(sData_or_uSize, uSize = None):
  return ctypes.create_unicode_buffer(sData_or_uSize, uSize);
