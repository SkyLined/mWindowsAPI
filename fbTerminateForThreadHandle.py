from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mTypes import *;

def fbTerminateForThreadHandle(hThread, nTimeoutInSeconds = None, bWait = True):
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  bTerminated = KERNEL32.TerminateThread(hThread, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the thread is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateThread(0x%08X, 0)" % (hThread.value,));
  sTerminateThreadResult = "TerminateThread(0x%08X, 0) %s" % \
      (hThread.value, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
  # Wait for the thread to die.
  return fbWaitForTerminationForThreadHandle(hThread, nTimeoutInSeconds if bWait else 0);
