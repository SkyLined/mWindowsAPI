from .cPipe import cPipe;
from .cProcess import cProcess;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

class cConsoleProcess(cProcess):
  @staticmethod
  def foGetForId(uProcessId):
    # Overwrite cProcess.foGetForId, as we cannot get the stdi/o streams for an existing process.
    raise NotImplementedError("This is not possible for console processes");
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
    # The output of oStdInPipe is inherited so the application can read from it when we write to the input.
    # The output of oStdInPipe is closed by us after the application is started, as we do not use it and
    # want Windows to clean it up when the application terminates.
    # The input of oStdOutPipe and oStdErrPipe are inherited so the the application can write to them.
    # The input of oStdOutPipe and oStdErrPipe are closed by us after the application is started, as we do
    # not use them and want Windows to clean them up when the application terminates.
    oStdInPipe = bRedirectStdIn and cPipe.foCreate("StdIn", bInheritableInput = False) or None;
    try:
      oStdOutPipe = bRedirectStdOut and cPipe.foCreate("StdOut", bInheritableOutput = False) or None;
      try:
        oStdErrPipe = bRedirectStdErr and cPipe.foCreate("StdErr", bInheritableOutput = False) or None;
        try:
          sCommandLine = " ".join([
            (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
            for s in [sBinaryPath] + asArguments
          ]);
          dwCreationFlags = DWORD(sum([
            bSuspended and CREATE_SUSPENDED or 0,
            bDebug and DEBUG_PROCESS or 0,
          ]));
          oStartupInfo = STARTUPINFOW();
          oStartupInfo.cb = fuSizeOf(oStartupInfo);
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
            dwCreationFlags, # dwCreationFlags
            NULL, # lpEnvironment
            sWorkingDirectory, # lpCurrentDirectory
            POINTER(oStartupInfo), # lpStartupInfo
            POINTER(oProcessInformation), # lpProcessInformation
          ):
            if not fbLastErrorIs(ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_INVALID_NAME):
              fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
                  (repr(sBinaryPath), repr(sCommandLine), dwCreationFlags.value, repr(sWorkingDirectory)));
            return None;
          # Close all handles that we no longer need:
          if not KERNEL32.CloseHandle(oProcessInformation.hThread):
            fThrowLastError("CloseHandle(0x%X)" % (oProcessInformation.hThread.value,));
          # Close the ends of the stdin/out/err pipes that we do not use; the child will keep them open until it dies
          # at which point they can be cleaned up because we are not keeping them open ourselves.
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
    cProcess.__init__(oSelf, uId, hProcess = hProcess);
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
  
  def __del__(oSelf):
    # Make sure all pipes are closed, so as not to cause a handle leak
    try:
      oSelf.fClose();
    except:
      pass;
  
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
  
