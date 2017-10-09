import ctypes;

CAST = ctypes.cast;
def POINTER(cType_or_xInstance):
  if type(cType_or_xInstance).__class__ == type:
    # If this is a type return a pointer-to-type.
    return ctypes.POINTER(cType_or_xInstance);
  else:
    # If this is an instance return a pointer to the instance.
    return ctypes.byref(cType_or_xInstance);

