from mWindowsSDK import *;
from .fbWaitForSingleObject import fbWaitForSingleObject;

def fbWaitForTerminationForProcessHandle(ohProcess, nTimeoutInSeconds = None):
  return fbWaitForSingleObject(ohProcess, nTimeoutInSeconds);
