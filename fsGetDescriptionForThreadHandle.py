from mWindowsSDK import *;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fsGetDescriptionForThreadHandle(ohThread):
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.GetThreadDescription:
    # This functions is new to Windows 10, so it may not exist.
    return None;
  opsDescription = PWSTR(); # PWSTR
  opopsDescription = opsDescription.foCreatePointer(); # PWSTR*
  if not oKernel32.GetThreadDescription(ohThread, opopsDescription):
    fThrowLastError("GetThreadDescription(%s, %s)" % (repr(ohThread), repr(opopsDescription)));
  uThreadDescriptionAddress = opsDescription.fuGetValue();
  sThreadDescription = fsGetStringAtAddress(uThreadDescriptionAddress) if not opsDescription.fbIsNULLPointer() else None;
  ohLocalThreadDescription = HLOCAL(uThreadDescriptionAddress);
  if not oKernel32.LocalFree(ohLocalThreadDescription).fbIsNULLPointer():
    fThrowLastError("LocalFree(%s)" % (repr(ohLocalThreadDescription),));
  return sThreadDescription;