from mWindowsSDK import *;
from .fbErrorIs import fbErrorIs;

def fbLastErrorIs(*tuAcceptableHResults):
  # Convert the last error to an HRESULT and see if it is in a list of acceptable errors.
  oKernel32 = foLoadKernel32DLL();
  odwLastError = oKernel32.GetLastError();
  ohResult = HRESULT_FROM_WIN32(odwLastError.value);
  return fbErrorIs(ohResult, *tuAcceptableHResults);
