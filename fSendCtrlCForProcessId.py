from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fThrowLastError import fThrowLastError;

def fSendCtrlCForProcessId(uProcessId):
  if not oKernel32DLL.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId):
    fThrowLastError("GenerateConsoleCtrlEvent(0x%08X, %d/0x%X)" % (CTRL_BREAK_EVENT, uProcessId, uProcessId,));
