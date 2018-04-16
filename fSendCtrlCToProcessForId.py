from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fSendCtrlCToProcessForId(uProcessId):
  KERNEL32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId) \
      or fThrowError("GenerateConsoleCtrlEvent(0x%08X, %d/0x%X)" % (CTRL_BREAK_EVENT, uProcessId, uProcessId,));
