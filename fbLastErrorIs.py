from .fbErrorIs import fbErrorIs;
from .mFunctions import *;
from .mDLLs import KERNEL32;

def fbLastErrorIs(*tuAcceptableHResults):
  # Convert the last error to an HRESULT and see if it is in a list of acceptable errors.
  dwLastError = KERNEL32.GetLastError();
  hResult = HRESULT_FROM_WIN32(dwLastError.value);
  return fbErrorIs(hResult, *tuAcceptableHResults);
