from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fuGetExitCodeForProcessHandle(ohProcess):
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  if fbIsRunningForProcessHandle(ohProcess):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32.GetExitCodeProcess(ohProcess, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeProcess(0x%08X, 0x%X)" % (ohProcess.value, odwExitCode.fuGetAddress()));
  return odwExitCode.value;
