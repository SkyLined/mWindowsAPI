from mWindowsSDK import *;

def fbIsValidHandle(ohSubject):
  assert isinstance(ohSubject, HANDLE), \
      "%s is not a HANDLE" % repr(ohSubject);
  return ohSubject.value not in [0, INVALID_HANDLE_VALUE];