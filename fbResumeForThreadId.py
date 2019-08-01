from mWindowsSDK import *;
from .fbResumeForThreadHandle import fbResumeForThreadHandle;
from .fohOpenForThreadIdAndDesiredAccess import fohOpenForThreadIdAndDesiredAccess;
from .fThrowError import fThrowError;

def fbResumeForThreadId(uThreadId):
  # A thread can be suspended multiple times. This function returns True if the thread is suspended 0 times after
  # returning.
  # Try to open the thread so we can terminate it...
  ohThread = fohOpenForThreadIdAndDesiredAccess(uThreadId, THREAD_SUSPEND_RESUME);
  bSuccess = False;
  try:
    # We can open the thread: try to terminate it.
    bResult = fbResumeForThreadHandle(ohThread);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohThread) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohThread.value,));
  return bResult;
