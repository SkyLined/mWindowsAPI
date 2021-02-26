from mWindowsSDK import *;
from fThrowWin32Error import fThrowWin32Error;

def fThrowLastError(sFailedOperation):
  oKernel32 = foLoadKernel32DLL();
  odwLastError = oKernel32.GetLastError();
  return fThrowWin32Error(sFailedOperation, odwLastError.fuGetValue());
