from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbWaitForTerminationForThreadHandle(ohThread, nTimeoutInSeconds = None):
  return fbWaitForSingleObject(ohThread, nTimeoutInSeconds, bInvalidHandleMeansSignaled = True);
