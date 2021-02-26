from mWindowsSDK import *;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fuGetExitCodeForProcessHandle(ohProcess):
  oKernel32 = foLoadKernel32DLL();
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  if fbIsRunningForProcessHandle(ohProcess):
    # Still running; no exit code.
    return None;
  odwExitCode = DWORD();
  if not oKernel32.GetExitCodeProcess(ohProcess, odwExitCode.foCreatePointer()):
    fThrowLastError("GetExitCodeProcess(%s, 0x%X)" % (repr(ohProcess), odwExitCode.fuGetAddress()));
  return odwExitCode.value;
