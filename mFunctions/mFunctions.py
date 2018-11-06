import ctypes;
from ..fsGetPythonISA import fsGetPythonISA;

fxCast = lambda cType, oInstance: ctypes.cast(oInstance, cType);
fuSizeOf = ctypes.sizeof;
fuAddressOf = ctypes.addressof;

def BUFFER(uSize):
  oBuffer = (ctypes.c_byte * uSize)();
  for uIndex in xrange(uSize):
    oBuffer[uIndex] = 0;
  return oBuffer;

def HRESULT_FROM_WIN32(uWin32):
  from ..mTypes import HANDLE;
  assert uWin32 & 0xFFFF0000 == 0, \
      "Invalid WIN32 value 0x%X" % uWin32;
  return HANDLE(0x80070000 + uWin32);

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

def STR(sData_or_uSize, uSize = None):
  return ctypes.create_string_buffer(sData_or_uSize, uSize);

def FAILED(xResult):
  from ..mTypes import HANDLE, NTSTATUS;
  assert isinstance(xResult, HANDLE) or isinstance(xResult, NTSTATUS), \
      "xResult %s is not a HANDLE or NTSTATUS" % repr(xResult);
  return xResult.value >= 0x80000000;

def SUCCEEDED(xResult):
  from ..mTypes import HANDLE, NTSTATUS;
  assert isinstance(xResult, HANDLE) or isinstance(xResult, NTSTATUS), \
      "xResult %s is not a HANDLE or NTSTATUS" % repr(xResult);
  return xResult.value < 0x80000000;

def WIN32_FROM_HRESULT(hResult):
  from ..mTypes import HANDLE;
  assert isinstance(hResult, HANDLE), \
      "%s is not a HANDLE" % repr(hResult);
  assert hResult.value & 0xFFFF0000 == 0x80070000, \
      "Invalid hResult value 0x%08X" % hResult.value;
  return hResult.value & 0xFFFF;

def WSTR(sData_or_uSize, uSize = None):
  return ctypes.create_unicode_buffer(sData_or_uSize, uSize);

def fuPointerValue(pxInstance):
  from ..mTypes import DWORD, QWORD;
  # Convert pointer to DWORD or QWORD depending on pointer size and return value;
  cWordType = {4: DWORD, 8: QWORD}[fuSizeOf(pxInstance)];
  return cWordType.from_buffer(pxInstance).value;
#  if pxInstance.__class__ in [cPOINTER_32, cPOINTER_64, ctypes.c_void_p]:
#    return pxInstance.value;
#  if pxInstance.__class__ in [ctypes.c_char_p, ctypes.c_wchar_p]:
#    return ctypes.c_void_p.from_buffer(pxInstance).value;
#  return fuAddressOf(pxInstance.contents) if pxInstance.contents is not None else 0;
#  try:
#  except TypeError:
#    raise TypeError("Cannot get the pointer value of a %s (%s)" % (type(pxInstance), repr(pxInstance)));

def fxPointerTarget(pxInstance):
  assert not pxInstance.__class__ in [cPOINTER_32, cPOINTER_64, ctypes.c_void_p], \
      "Unfortunately, this is not implemented";
  if pxInstance.__class__ in [ctypes.c_char_p, ctypes.c_wchar_p]:
    return pxInstance.value;
  return pxInstance.contents;

def fbIsValidPointer(hInstance):
  return fuPointerValue(hInstance) != 0;

def fbIsValidHandle(hInstance):
  from ..mDefines import INVALID_HANDLE_VALUE;
  from ..mTypes import HANDLE;
  assert isinstance(hInstance, HANDLE), \
      "%s is not a HANDLE" % repr(hInstance);
  return hInstance.value not in [0, INVALID_HANDLE_VALUE];

