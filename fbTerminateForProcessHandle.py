from mWindowsSDK import *;
from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fbTerminateForProcessHandle(ohProcess, nTimeoutInSeconds = None, bWait = True):
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  assert ohProcess != 0, \
      "Cannot terminate a NULL HANDLE";
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  oKernel32 = foLoadKernel32DLL();
  bTerminated = oKernel32.TerminateProcess(ohProcess, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the process is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateProcess(%s, 0)" % (repr(ohProcess),));
  # Wait for the process to die.
  return fbWaitForTerminationForProcessHandle(ohProcess, nTimeoutInSeconds if bWait else 0);
