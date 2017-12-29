from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from cPipe import cPipe;
from cProcessInformation import cProcessInformation;
from fbIsProcessRunningForHandle import fbIsProcessRunningForHandle;
from fbIsProcessRunningForId import fbIsProcessRunningForId;
from fbTerminateProcessForHandle import fbTerminateProcessForHandle;
from fbTerminateProcessForId import fbTerminateProcessForId;
from fbWaitForProcessTerminationForHandle import fbWaitForProcessTerminationForHandle;
from fbWaitForProcessTerminationForId import fbWaitForProcessTerminationForId;
from fThrowError import fThrowError;
from fuGetProcessExitCodeForHandle import fuGetProcessExitCodeForHandle;
from fuGetProcessExitCodeForId import fuGetProcessExitCodeForId;

class cConsoleProcess(object):
  @staticmethod
  def foCreateForBinaryPathAndArguments(
    sBinaryPath,
    asArguments,
    sWorkingDirectory = None,
    bRedirectStdIn = True,
    bRedirectStdOut = True,
    bRedirectStdErr = True,
    bSuspended = False,
    bDebug = False,
  ):
    oStdInPipe = bRedirectStdIn and cPipe("StdIn", bInheritableInput = False) or None;
    try:
      oStdOutPipe = bRedirectStdOut and cPipe("StdOut", bInheritableOutput = False) or None;
      try:
        oStdErrPipe = bRedirectStdErr and cPipe("StdErr", bInheritableOutput = False) or None;
        try:
          sCommandLine = " ".join([
            (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
            for s in [sBinaryPath] + asArguments
          ]);
          uCreationFlags = sum([
            bSuspended and CREATE_SUSPENDED or 0,
            bDebug and DEBUG_PROCESS or 0,
          ]);
          oStartupInfo = STARTUPINFOW();
          oStartupInfo.cb = SIZEOF(oStartupInfo);
          oStartupInfo.lpDesktop = NULL;
          oStartupInfo.lpDesktop = NULL;
          oStartupInfo.dwFlags = STARTF_USESTDHANDLES;
          oStartupInfo.hStdInput = oStdInPipe and oStdInPipe.hOutput or KERNEL32.GetStdHandle(STD_INPUT_HANDLE);
          oStartupInfo.hStdOutput = oStdOutPipe and oStdOutPipe.hInput or KERNEL32.GetStdHandle(STD_OUTPUT_HANDLE);
          oStartupInfo.hStdError = oStdErrPipe and oStdErrPipe.hInput or KERNEL32.GetStdHandle(STD_ERROR_HANDLE);
          oProcessInformation = PROCESS_INFORMATION();
          
          if not KERNEL32.CreateProcessW(
            sBinaryPath, # lpApplicationName
            sCommandLine, # lpCommandLine
            NULL, # lpProcessAttributes
            NULL, # lpThreadAttributes
            TRUE, # bInheritHandles
            uCreationFlags, # dwCreationFlags
            NULL, # lpEnvironment
            sWorkingDirectory, # lpCurrentDirectory
            POINTER(oStartupInfo), # lpStartupInfo
            POINTER(oProcessInformation), # lpProcessInformation
          ):
            uCreateProcessError = KERNEL32.GetLastError();
            (HRESULT_FROM_WIN32(uCreateProcessError) in [ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME]) \
                or fThrowError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
                (repr(sBinaryPath), repr(sCommandLine), uCreationFlags, sWorkingDirectory), uCreateProcessError);
            return None;
          # Close all handles that we no longer need:
          KERNEL32.CloseHandle(oProcessInformation.hThread) \
              or fThrowError("CloseHandle(0x%X)" % (oProcessInformation.hThread,));
          # We use one end of the stdin/out/err pipes and the child uses the other. However, we still have the other
          # ends open as well. We should close them because otherwise the pipes will not be closed when the child
          # terminates (because we are keeping them open).
          oStdInPipe and oStdInPipe.fClose(bOutput = True); 
          oStdOutPipe and oStdOutPipe.fClose(bInput = True);
          oStdErrPipe and oStdErrPipe.fClose(bInput = True);
          return cConsoleProcess(oProcessInformation.dwProcessId, oStdInPipe, oStdOutPipe, oStdErrPipe, hProcess = oProcessInformation.hProcess);
        except:
          oStdErrPipe and oStdErrPipe.fClose();
          raise;
      except:
        oStdOutPipe and oStdOutPipe.fClose();
        raise;
    except:
      oStdInPipe and oStdInPipe.fClose();
      raise;
  
  def __init__(oSelf, uId, oStdInPipe, oStdOutPipe, oStdErrPipe, hProcess = None):
    oSelf.uId = uId;
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
    oSelf.__oInformation = None;
    oSelf.__hProcess = hProcess;
  
  def __del__(oSelf):
    KERNEL32.CloseHandle(oSelf.__hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (oSelf.__hProcess,));
  
  @property
  def bIsRunning(oSelf):
    if oSelf.__hProcess:
      return fbIsProcessRunningForHandle(oSelf.__hProcess);
    return fbIsProcessRunningForId(oSelf.uId);
  
  def fClose(oSelf):
    # This will attemp to close all pipes, even if an exception is thrown when closing one of them. If multiple pipes
    # throw exceptions, all but one are ignored.
    try:
      oSelf.oStdInPipe and oSelf.oStdInPipe.fClose();
    finally:
      try:
        oSelf.oStdOutPipe and oSelf.oStdOutPipe.fClose();
      finally:
        oSelf.oStdErrPipe and oSelf.oStdErrPipe.fClose();
  
  def fbTerminate(oSelf, uTimeout = None):
    if oSelf.__hProcess:
      return fbTerminateProcessForHandle(oSelf.__hProcess, uTimeout);
    return fbTerminateProcessForId(oSelf.uId, uTimeout);
  
  def fbWait(oSelf, uTimeout = None):
    if oSelf.__hProcess:
      return fbWaitForProcessTerminationForHandle(oSelf.__hProcess, uTimeout);
    return fbWaitForProcessTerminationForId(oSelf.uId, uTimeout);
  
  @property
  def uExitCode(oSelf):
    if oSelf.__hProcess:
      return fuGetProcessExitCodeForHandle(oSelf.__hProcess);
    return fuGetProcessExitCodeForId(oSelf.uId);
  
  @property
  def oInformation(oSelf):
    if oSelf.__oInformation is None:
      oSelf.__oInformation = cProcessInformation.foGetForId(oSelf.uId);
    return oSelf.__oInformation;
  
  @property
  def sISA(oSelf):
    return oSelf.oInformation.sISA;
  
  @property
  def uBinaryStartAddress(oSelf):
    return oSelf.oInformation.uBinaryStartAddress;
  
  @property
  def sBinaryPath(oSelf):
    return oSelf.oInformation.sBinaryPath;
  
  @property
  def sBinaryName(oSelf):
    return oSelf.oInformation.sBinaryName;
  
  @property
  def sCommandLine(oSelf):
    return oSelf.oInformation.sCommandLine;
