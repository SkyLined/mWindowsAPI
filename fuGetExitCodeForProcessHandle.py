from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fThrowLastError import fThrowLastError;
from .mDefines import STILL_ACTIVE;
from .mDLLs import KERNEL32;
from .mFunctions import POINTER;
from .mTypes import DWORD;

def fuGetExitCodeForProcessHandle(hProcess):
  if fbIsRunningForProcessHandle(hProcess):
    # Still running; no exit code.
    return None;
  dwExitCode = DWORD();
  if not KERNEL32.GetExitCodeProcess(hProcess, POINTER(dwExitCode)):
    fThrowLastError("GetExitCodeProcess(0x%08X, 0x%X)" % (hProcess.value, fuAddressOf(dwExitCode)));
  return dwExitCode.value;
