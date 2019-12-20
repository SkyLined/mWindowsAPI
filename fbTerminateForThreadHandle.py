from mWindowsSDK import *;
from .fbLastErrorIs import fbLastErrorIs;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fThrowLastError import fThrowLastError;

def fbTerminateForThreadHandle(ohThread, nTimeoutInSeconds = None, bWait = True):
  assert bWait or nTimeoutInSeconds is None, \
      "Invalid arguments nTimeoutInSeconds = %f and bWait = %s" % (nTimeoutInSeconds, bWait);
  oKernel32 = foLoadKernel32DLL();
  bTerminated = oKernel32.TerminateThread(ohThread, 0);
  if not bTerminated:
    # ERROR_ACCESS_DENIED may indicate the thread is already terminating/terminated.
    # Other errors are unexpected.
    if not fbLastErrorIs(ERROR_ACCESS_DENIED):
      fThrowLastError("TerminateThread(0x%08X, 0)" % (ohThread.value,));
  # Wait for the thread to die.
  return fbWaitForTerminationForThreadHandle(ohThread, nTimeoutInSeconds if bWait else 0);
