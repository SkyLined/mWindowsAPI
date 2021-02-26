from mWindowsSDK import *;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .foh0OpenForThreadIdAndDesiredAccess import foh0OpenForThreadIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def fbIsRunningForThreadId(uThreadId, bMustGetAccess = True):
  # A thread can be suspended multiple times. This function returns True if the
  # thread is suspended 0 times after returning.
  # Try to open the thread. If it does not exist, it will return None. If we
  # have no access rights, it will throw an error.
  oh0Thread = foh0OpenForThreadIdAndDesiredAccess(uThreadId, SYNCHORNIZE, bMustExist = False, bMustGetAccess = True);
  if oh0Thread is None:
    return False;
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbIsRunningForThreadHandle(ohThread);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohThread),));
  return bResult;
