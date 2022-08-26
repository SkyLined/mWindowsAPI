from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowWin32Error import fThrowWin32Error;

def fThrowLastError(sFailedOperation):
  mDebugOutput_HideInCallStack = True; # Hide this helper function in the call stack.
  odwLastError = oKernel32DLL.GetLastError();
  return fThrowWin32Error(sFailedOperation, odwLastError.fuGetValue());
