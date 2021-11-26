from .fThrowLastError import fThrowLastError;
from mWindowsSDK.mKernel32 import oKernel32DLL;

def fStopDebuggingForProcessId(uProcessId):
  if not oKernel32DLL.DebugActiveProcessStop(uProcessId):
    fThrowLastError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
