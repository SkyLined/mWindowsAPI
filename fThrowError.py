from mWindowsSDK import *;

def fThrowError(sFailedOperation, uError):
  hResult = HRESULT_FROM_WIN32(uError);
  sHResult = "0x%08X" % hResult.value;
  for sErrorDefineName in dir(mErrorDefines):
    if getattr(mErrorDefines, sErrorDefineName) == hResult.value:
      sHResult += " (%s)" % sErrorDefineName;
      break;
  sErrorMessage = "%s => Win32 error 0x%X / HRESULT %s." % (sFailedOperation, uError, sHResult);
  if hResult.value in [ERROR_COMMITMENT_LIMIT, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY]:
    raise MemoryError(sErrorMessage);
  raise AssertionError(sErrorMessage);

