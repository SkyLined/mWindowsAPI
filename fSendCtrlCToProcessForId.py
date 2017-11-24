from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

def fSendCtrlCToProcessForId(uProcessId):
  assert KERNEL32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId), \
      fsGetErrorMessage("GenerateConsoleCtrlEvent(0x%08X, %d/0x%X)" % (CTRL_BREAK_EVENT, uProcessId, uProcessId,));
