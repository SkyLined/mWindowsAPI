from .fThrowLastError import fThrowLastError;

def fStopDebuggingForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.DebugActiveProcessStop(uProcessId):
    fThrowLastError("DebugActiveProcessStop(%d/0x%X)" % (uProcessId, uProcessId,));
