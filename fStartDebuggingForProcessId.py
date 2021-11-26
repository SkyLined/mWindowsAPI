from .fThrowLastError import fThrowLastError;
from mWindowsSDK.mKernel32 import oKernel32DLL;

def fStartDebuggingForProcessId(uProcessId):
  if not oKernel32DLL.DebugActiveProcess(uProcessId):
    fThrowLastError("fStartDebuggingForProcessId(%d/0x%X)" % (uProcessId, uProcessId,));
