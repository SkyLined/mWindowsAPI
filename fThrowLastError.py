from fThrowError import fThrowError;

def fThrowLastError(sFailedOperation):
  oKernel32 = foLoadKernel32DLL();
  odwLastError = oKernel32.GetLastError();
  return fThrowError(sFailedOperation, odwLastError.value);
