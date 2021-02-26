from mWindowsSDK import *;

def fbLastErrorIs(*tuAcceptableWin32ErrorCodes):
  # Convert the last error to an HRESULT and see if it is in a list of acceptable errors.
  oKernel32 = foLoadKernel32DLL();
  odwLastError = oKernel32.GetLastError();
  return odwLastError.fuGetValue() in tuAcceptableWin32ErrorCodes;
