from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fsGetDescriptionForThreadHandle(ohThread):
  if not oKernel32DLL.GetThreadDescription:
    # This functions is new to Windows 10, so it may not exist.
    return None;
  opsDescription = PWSTR(); # PWSTR
  opopsDescription = opsDescription.foCreatePointer(); # PWSTR*
  if not oKernel32DLL.GetThreadDescription(ohThread, opopsDescription):
    fThrowLastError("GetThreadDescription(%s, %s)" % (repr(ohThread), repr(opopsDescription)));
  uThreadDescriptionAddress = opsDescription.fuGetValue();
  sThreadDescription = fsGetStringAtAddress(uThreadDescriptionAddress) if not opsDescription.fbIsNULLPointer() else None;
  ohLocalThreadDescription = HLOCAL(uThreadDescriptionAddress);
  if not oKernel32DLL.LocalFree(ohLocalThreadDescription).fbIsNULLPointer():
    fThrowLastError("LocalFree(%s)" % (repr(ohLocalThreadDescription),));
  return sThreadDescription;