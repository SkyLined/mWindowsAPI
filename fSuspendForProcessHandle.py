from mWindowsSDK import *;
from .fThrowError import fThrowError;

def fSuspendForProcessHandle(ohProcess):
  oNTStatus = oNTDLL.NtSuspendProcess(ohProcess); # NOT RELIABLE!
  if NT_ERROR(oNTStatus):
    fThrowError("NtSuspendProcess(0x%08X)" % (ohProcess.value,), oNTStatus.value);
