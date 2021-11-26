from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fbTerminateForThreadHandle(ohThread, nTimeoutInSeconds = None, bWait = True):
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  obTerminated = oKernel32DLL.TerminateThread(ohThread, 0);
  if not obTerminated.fbGetValue():
    # ERROR_ACCESS_DENIED may indicate the thread is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateThread(%s, 0)" % (repr(ohThread),));
  # Wait for the thread to die.
  return fbWaitForTerminationForThreadHandle(ohThread, nTimeoutInSeconds if bWait else 0);
