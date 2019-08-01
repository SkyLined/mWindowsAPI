from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fbTerminateForThreadHandle(ohThread, nTimeoutInSeconds = None, bWait = True):
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  bTerminated = oKernel32.TerminateThread(ohThread, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the thread is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateThread(0x%08X, 0)" % (ohThread.value,));
  sTerminateThreadResult = "TerminateThread(0x%08X, 0) %s" % \
      (ohThread.value, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
  # Wait for the thread to die.
  return fbWaitForTerminationForThreadHandle(ohThread, nTimeoutInSeconds if bWait else 0);
