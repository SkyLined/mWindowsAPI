from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForProcessHandle(ohProcess):
  return fbWaitForSingleObject(ohProcess, 0);
