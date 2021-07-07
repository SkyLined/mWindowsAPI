from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def fbWaitForSingleObject(ohSubject, nTimeoutInSeconds = None, bInvalidHandleMeansSignaled = False):
  assert isinstance(ohSubject, HANDLE), \
      "%s is not a HANDLE" % repr(ohSubject);
  assert fbIsValidHandle(ohSubject), \
      "%s is not a valid handle" % repr(ohSubject);
  odwMilliseconds = DWORD(INFINITE if nTimeoutInSeconds is None else int(nTimeoutInSeconds * 1000));
  oKernel32 = foLoadKernel32DLL();
  odwResult = oKernel32.WaitForSingleObject(ohSubject, odwMilliseconds);
  if odwResult == WAIT_OBJECT_0:
    return True; # Object was signaled.
  if odwResult == WAIT_TIMEOUT:
    return False; # Timeout waiting for object.
  if odwResult == WAIT_FAILED:
    # Waiting for terminated processes and threads can fail with an
    # `ERROR_INVALID_HANDLE` error. Setting `bInvalidHandleMeansSignaled` to
    # True will cause this function to return `True` in that case.
    if bInvalidHandleMeansSignaled and fbLastErrorIs(ERROR_INVALID_HANDLE):
      return True;
    sTimeoutDescription = "INFINITE" if nTimeoutInSeconds is None else "%d" % odwMilliseconds;
    fThrowLastError("WaitForSingleObject(%s, %s) = %s" % (repr(ohSubject), sTimeoutDescription, repr(odwResult)));
  # return value unexpected.
  sTimeoutDescription = "INFINITE" if nTimeoutInSeconds is None else "%d" % odwMilliseconds;
  raise AsserionError("WaitForSingleObject(%s, %s) = 0x%X!?" % (repr(ohSubject), sTimeoutDescription, repr(odwResult)));
