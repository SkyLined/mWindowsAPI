from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;

def fbLastErrorFailed():
  odwLastError = oKernel32DLL.GetLastError();
  return odwLastError != 0;
