from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForProcessHandle(ohProcess):
  return not fbWaitForSingleObject(ohProcess, nTimeoutInSeconds = 0, bInvalidHandleIsAcceptable = True);
