from mWindowsAPI import *;

def fSendCtrlCToProcessForId(uProcessId):
  assert KERNEL32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, uProcessId), \
      "KERNEL32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, %d/0x%X) => Error 0x%X." % (uProcessId, uProcessId, KERNEL32.GetLastError());
