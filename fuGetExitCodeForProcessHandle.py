from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fuGetExitCodeForProcessHandle(ohProcess):
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  if fbIsRunningForProcessHandle(ohProcess):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32DLL.GetExitCodeProcess(ohProcess, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeProcess(%s, 0x%X)" % (repr(ohProcess), odwExitCode.fuGetAddress()));
  return odwExitCode.value;
