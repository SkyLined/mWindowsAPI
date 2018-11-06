from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbWaitForTerminationForThreadHandle(hThread, nTimeoutInSeconds = None):
  return fbWaitForSingleObject(hThread, nTimeoutInSeconds);
