from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForThreadHandle(ohThread):
  return fbWaitForSingleObject(ohThread, 0);
