from mWindowsSDK import *;
from .fThrowNTStatusError import fThrowNTStatusError;

def fSuspendForProcessHandle(ohProcess):
  oNTDLL = foLoadNTDLL();
  oNTStatus = oNTDLL.NtSuspendProcess(ohProcess); # NOT RELIABLE!
  if not NT_SUCCESS(oNTStatus):
    fThrowNTStatusError(
      "NtSuspendProcess(%s)" % (repr(ohProcess),),
      oNTStatus.fuGetValue()
    );
