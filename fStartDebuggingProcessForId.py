from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from fThrowError import fThrowError;

def fStartDebuggingProcessForId(uProcessId):
  KERNEL32.DebugActiveProcess(uProcessId) \
      or fThrowError("fStartDebuggingProcessForId(%d/0x%X)" % (uProcessId, uProcessId,));
