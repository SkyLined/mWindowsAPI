from .mFunctions import *;
from .mDLLs import KERNEL32;

def fbLastErrorFailed():
  dwLastError = KERNEL32.GetLastError();
  return dwLastError.value != 0;
