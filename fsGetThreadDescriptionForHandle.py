from .mDefines import STILL_ACTIVE;
from .mFunctions import CAST, POINTER, POINTER_TARGET, POINTER_VALUE;
from .mTypes import HLOCAL, PWSTR;
from .mDLLs import KERNEL32;
from .fbIsThreadRunningForHandle import fbIsThreadRunningForHandle;
from .fThrowError import fThrowError;

def fsGetThreadDescriptionForHandle(hThread):
  psDescription = PWSTR();
  KERNEL32.GetThreadDescription(hThread, POINTER(psDescription)) \
      or fThrowError("GetThreadDescription(0x%X, ...)" % (hThread,));
  try:
    return POINTER_VALUE(psDescription) and POINTER_TARGET(psDescription)[:] or None;
  finally:
    KERNEL32.LocalFree(CAST(HLOCAL, psDescription)) == None \
        or fThrowError("LocalFree(0x%X)" % (POINTER_VALUE(psDescription),));
