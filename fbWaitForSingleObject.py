from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fbWaitForSingleObject(ohSubject, nTimeoutInSeconds = None):
  assert isinstance(ohSubject, HANDLE), \
      "%s is not a HANDLE" % repr(ohSubject);
  assert ohSubject.value != INVALID_HANDLE_VALUE, \
      "%s is INVALID_HANDLE_VALUE" % repr(ohSubject);
  odwMilliseconds = DWORD(INFINITE if nTimeoutInSeconds is None else long(nTimeoutInSeconds * 1000));
  oKernel32 = foLoadKernel32DLL();
  odwResult = oKernel32.WaitForSingleObject(ohSubject, odwMilliseconds);
  if odwResult.value == WAIT_OBJECT_0:
    return True; # Object was signaled.
  if odwResult.value == WAIT_TIMEOUT:
    return False; # Timeout waiting for object.
  if odwResult.value == WAIT_FAILED:
    fThrowLastError("WaitForSingleObject(0x%X, %s) = 0x%X" % (ohSubject.value, "INFINITE" if nTimeoutInSeconds is None else "%d" % odwMilliseconds.value, odwResult.value));
  # return value unexpected.
  raise AsserionError("WaitForSingleObject(0x%X, %s) = 0x%X!?" % (ohSubject.value, "INFINITE" if nTimeoutInSeconds is None else "%d" % odwMilliseconds.value, odwResult.value));
