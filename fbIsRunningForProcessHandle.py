from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForProcessHandle(ohProcess):
  return not fbWaitForSingleObject(ohProcess, 0);
