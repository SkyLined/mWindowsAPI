from mWindowsSDK import *;

def fThrowNTStatusError(sFailedOperation, uNTStatus):
  sErrorMessage = "%s => %s." % (sFailedOperation, fsGetNTStatusDescription(uNTStatus));
  if uNTStatus in [STATUS_NO_MEMORY]:
    raise MemoryError(sErrorMessage);
  raise WindowsError(uNTStatus, sErrorMessage);

