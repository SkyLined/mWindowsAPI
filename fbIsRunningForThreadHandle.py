from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbIsRunningForThreadHandle(hThread):
  return fbWaitForSingleObject(hThread, 0);
