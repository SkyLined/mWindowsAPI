from .fbWaitForSingleObject import fbWaitForSingleObject;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fbWaitForTerminationForProcessHandle(hProcess, nTimeoutInSeconds = None):
  return fbWaitForSingleObject(hProcess, nTimeoutInSeconds);
