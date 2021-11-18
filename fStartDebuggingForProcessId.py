from .fThrowLastError import fThrowLastError;

def fStartDebuggingForProcessId(uProcessId):
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  if not oKernel32DLL.DebugActiveProcess(uProcessId):
    fThrowLastError("fStartDebuggingForProcessId(%d/0x%X)" % (uProcessId, uProcessId,));
