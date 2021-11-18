from mWindowsSDK import *;
from .fThrowWin32Error import fThrowWin32Error;

def fThrowLastError(sFailedOperation):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  odwLastError = oKernel32DLL.GetLastError();
  return fThrowWin32Error(sFailedOperation, odwLastError.fuGetValue());
