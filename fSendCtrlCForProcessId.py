from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowLastError import fThrowLastError;

def fSendCtrlCForProcessId(uProcessId):
  if not KERNEL32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId):
    fThrowLastError("GenerateConsoleCtrlEvent(0x%08X, %d/0x%X)" % (CTRL_BREAK_EVENT, uProcessId, uProcessId,));
