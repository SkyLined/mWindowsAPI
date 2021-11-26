from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowWin32Error import fThrowWin32Error;

def fThrowLastError(sFailedOperation):
  odwLastError = oKernel32DLL.GetLastError();
  return fThrowWin32Error(sFailedOperation, odwLastError.fuGetValue());
