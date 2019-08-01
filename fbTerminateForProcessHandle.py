from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fThrowLastError import fThrowLastError;

def fbTerminateForProcessHandle(ohProcess, nTimeoutInSeconds = None, bWait = True):
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  assert ohProcess.value is not None, \
      "Cannot terminate a NULL HANDLE";
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  bTerminated = oKernel32.TerminateProcess(ohProcess, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the process is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateProcess(0x%08X, 0)" % (ohProcess.value,));
  sTerminateProcessResult = "TerminateProcess(0x%08X, 0) %s" % \
      (ohProcess.value, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
  # Wait for the process to die.
  return fbWaitForTerminationForProcessHandle(ohProcess, nTimeoutInSeconds if bWait else 0);
