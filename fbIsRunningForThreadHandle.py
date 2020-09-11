from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForThreadHandle(ohThread):
  return not fbWaitForSingleObject(ohThread, 0);
