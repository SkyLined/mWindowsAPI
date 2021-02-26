from mWindowsSDK import *;

def fbLastErrorFailed():
  oKernel32 = foLoadKernel32DLL();
  odwLastError = oKernel32.GetLastError();
  return odwLastError != 0;
