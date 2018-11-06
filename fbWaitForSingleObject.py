from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbWaitForSingleObject(hObject, nTimeoutInSeconds = None):
  dwMilliseconds = DWORD(INFINITE if nTimeoutInSeconds is None else long(nTimeoutInSeconds * 1000));
  dwResult = KERNEL32.WaitForSingleObject(hObject, dwMilliseconds);
  if dwResult.value == WAIT_TIMEOUT:
    return False; # Timeout waiting for object.
  if dwResult.value == WAIT_OBJECT_0:
    return True; # Object was signaled.
  fThrowLastError("WaitForSingleObject(0x%08X, %s) = 0x%08X" % (hObject.value, "INFINITE" if nTimeoutInSeconds is None else "%d" % dwMilliseconds.value, dwResult.value));
