from mWindowsSDK import *;
from .fThrowLastError import fThrowLastError;

def fSendCtrlCForProcessId(uProcessId):
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId):
    fThrowLastError("GenerateConsoleCtrlEvent(0x%08X, %d/0x%X)" % (CTRL_BREAK_EVENT, uProcessId, uProcessId,));
