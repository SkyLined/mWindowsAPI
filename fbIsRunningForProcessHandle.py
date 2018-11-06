from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForProcessHandle(hProcess):
  return fbWaitForSingleObject(hProcess, 0);
