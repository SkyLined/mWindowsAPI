from mWindowsSDK import *;

def fThrowNTStatusError(sFailedOperation, uNTStatus):
  sErrorMessage = "%s => %s." % (sFailedOperation, fsGetNTStatusDescription(uNTStatus));
  if uNTStatus in [STATUS_NO_MEMORY]:
    raise MemoryError(sErrorMessage);
  # Python uses a "long", which is signed. We cannot simply pass uNTStatus but
  # must convert it to 
  iNTStatus = uNTStatus - (0 if uNTStatus < (1 << 31) else (1<<32));
  raise WindowsError(iNTStatus, sErrorMessage);

