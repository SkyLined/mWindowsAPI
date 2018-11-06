from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fsGetDescriptionForThreadHandle(hThread):
  psDescription = PWSTR();
  if not KERNEL32.GetThreadDescription(hThread, POINTER(psDescription)):
    fThrowLastError("GetThreadDescription(0x%X, ...)" % (hThread.value,));
  bSuccess = False;
  try:
    sThreadDescription = fxPointerTarget(psDescription)[:] if fbIsValidPointer(psDescription) else None;
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if fuPointerValue(KERNEL32.LocalFree(fxCast(HLOCAL, psDescription))) and bSuccess:
      fThrowLastError("LocalFree(0x%X)" % (fuPointerValue(psDescription),));
  return sThreadDescription;