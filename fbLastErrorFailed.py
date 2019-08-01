from mWindowsSDK import *;
from .mDLLs import oKernel32;

def fbLastErrorFailed():
  odwLastError = oKernel32.GetLastError();
  return odwLastError.value != 0;
