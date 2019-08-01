from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fsGetDescriptionForThreadHandle(ohThread):
  psDescription = PWSTR();
  if not oKernel32.GetThreadDescription(ohThread, psDescription.foCreatePointer()):
    fThrowLastError("GetThreadDescription(0x%X, ...)" % (ohThread.value,));
  uThreadDescriptionAddress = psDescription.value;
  sThreadDescription = fsGetStringAtAddress(uThreadDescriptionAddress) if not psDescription.fbIsNULLPointer() else None;
  if not oKernel32.LocalFree(HLOCAL(uThreadDescriptionAddress)).fbIsNULLPointer():
    fThrowLastError("LocalFree(0x%X)" % (uThreadDescriptionAddress,));
  return sThreadDescription;