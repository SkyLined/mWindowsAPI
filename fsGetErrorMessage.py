from mFunctions import HRESULT_FROM_WIN32;
from mDLLs import KERNEL32;

def fsGetErrorMessage(sFailedOperation, uError = None):
  if uError is None:
    uError = KERNEL32.GetLastError();
  return "%s => Win32 error 0x%X / HRESULT 0x%08X." % (sFailedOperation, uError, HRESULT_FROM_WIN32(uError));
