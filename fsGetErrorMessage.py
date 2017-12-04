from mFunctions import HRESULT_FROM_WIN32;
from mDLLs import KERNEL32;
from mDefines import mErrorDefines;

def fsGetErrorMessage(sFailedOperation, uError = None):
  if uError is None:
    uError = KERNEL32.GetLastError();
  uHResult = HRESULT_FROM_WIN32(uError);
  for sErrorDefineName in dir(mErrorDefines):
    if getattr(mErrorDefines, sErrorDefineName) == uHResult:
      sHResult = " (%s)" % sErrorDefineName;
      break;
  else:
    sHResult = "";
  return "%s => Win32 error 0x%X / HRESULT 0x%08X%s." % (sFailedOperation, uError, uHResult, sHResult);
