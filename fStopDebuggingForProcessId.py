from .fThrowLastError import fThrowLastError;

def fStopDebuggingForProcessId(uProcessId):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  if not oKernel32DLL.DebugActiveProcessStop(uProcessId):
    fThrowLastError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
