from fThrowError import fThrowError;
from .mFunctions import *;
from .mDLLs import KERNEL32;

def fThrowLastError(sFailedOperation):
  dwLastError = KERNEL32.GetLastError();
  return fThrowError(sFailedOperation, dwLastError.value);
