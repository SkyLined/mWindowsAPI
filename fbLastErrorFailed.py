from mWindowsSDK import *;

def fbLastErrorFailed():
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  odwLastError = oKernel32DLL.GetLastError();
  return odwLastError != 0;
