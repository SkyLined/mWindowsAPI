from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbTerminateForProcessHandle(hProcess, nTimeoutInSeconds = None, bWait = True):
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  bTerminated = KERNEL32.TerminateProcess(hProcess, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the process is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateProcess(0x%08X, 0)" % (hProcess.value,));
  sTerminateProcessResult = "TerminateProcess(0x%08X, 0) %s" % \
      (hProcess.value, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
  # Wait for the process to die.
  return fbWaitForTerminationForProcessHandle(hProcess, nTimeoutInSeconds if bWait else 0);
