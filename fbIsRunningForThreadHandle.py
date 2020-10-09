from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForThreadHandle(ohThread):
  return not fbWaitForSingleObject(ohThread, nTimeoutInSeconds = 0, bInvalidHandleIsAcceptable = True);
