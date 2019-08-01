from .fThrowLastError import fThrowLastError;

def fStartDebuggingForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.DebugActiveProcess(uProcessId):
    fThrowLastError("fStartDebuggingForProcessId(%d/0x%X)" % (uProcessId, uProcessId,));
