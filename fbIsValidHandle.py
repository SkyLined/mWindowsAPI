from mWindowsSDK import *;

def fbIsValidHandle(oh0Subject):
  if oh0Subject is None: return False;
  assert isinstance(oh0Subject, HANDLE), \
      "%s is not a HANDLE" % repr(oh0Subject);
  return oh0Subject.fuGetValue() not in [0, INVALID_HANDLE_VALUE];