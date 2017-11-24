import ctypes;

CAST = lambda cType, oInstance: ctypes.cast(oInstance, cType);
SIZEOF = ctypes.sizeof;

def BUFFER(uSize):
  oBuffer = (ctypes.c_byte * uSize)();
  for uIndex in xrange(uSize):
    oBuffer[uIndex] = 0;
  return oBuffer;

def HRESULT_FROM_WIN32(uWin32):
  return 0x80070000 + uWin32;

def POINTER(cType_or_xInstance):
  if type(cType_or_xInstance).__class__ == type:
    # If this is a type return a pointer-to-type.
    return ctypes.POINTER(cType_or_xInstance);
  else:
    # If this is an instance return a pointer to the instance.
    return ctypes.byref(cType_or_xInstance);

def POINTER_32(cType_or_uAddress = None):
  if cType_or_uAddress is None or type(cType_or_uAddress).__class__ == type:
    return ctypes.c_ulong;
  return ctypes.c_ulong(cType_or_uAddress);

def POINTER_64(cType_or_uAddress = None):
  if cType_or_uAddress is None or type(cType_or_uAddress).__class__ == type:
    return ctypes.c_ulonglong;
  return ctypes.c_ulonglong(cType_or_uAddress);

def STR(sData_or_uSize, uSize = None):
  return ctypes.create_string_buffer(sData_or_uSize, uSize);

def SUCCEEDED(uHResult):
  return uHResult < 0x80000000;

def WIN32_FROM_HRESULT(hResult):
  assert hResult & 0xFFFF0000 == 0x80070000;
  return hResult &0xFFFF;

def WSTR(sData_or_uSize, uSize = None):
  return ctypes.create_unicode_buffer(sData_or_uSize, uSize);

