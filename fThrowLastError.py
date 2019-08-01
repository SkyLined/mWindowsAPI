from .mDLLs import oKernel32;
from fThrowError import fThrowError;

def fThrowLastError(sFailedOperation):
  odwLastError = oKernel32.GetLastError();
  return fThrowError(sFailedOperation, odwLastError.value);
