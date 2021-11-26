from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;

def fbLastErrorIs(*tuAcceptableWin32ErrorCodes):
  # Convert the last error to an HRESULT and see if it is in a list of acceptable errors.
  odwLastError = oKernel32DLL.GetLastError();
  return odwLastError.fuGetValue() in tuAcceptableWin32ErrorCodes;
