from mWindowsSDK import *;
from .cPipe import cPipe;
from .cProcess import cProcess;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

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
    bHidden = False,
    bMinimizedWindow = False,
    bNormalWindow = False,
    bMaximizedWindow = False,
  ):
    # Default to hidden of no visibility flags are provided.
    asWindowSpecificFlags = [sFlagName for (bValue, sFlagName) in {
      bHidden: "bHidden",
      bMinimizedWindow: "bMinimizedWindow",
      bNormalWindow: "bNormalWindow",
      bMaximizedWindow: "bMaximizedWindow",
    }.items() if bValue];
    bSeparateWindow = len(asWindowSpecificFlags) != 0;
    if bSeparateWindow:
      assert len(asWindowSpecificFlags) == 1, \
          "Cannot set the following arguments to True at the same time: %s" % (", ".join(asWindowSpecificFlags),);
      assert not (bRedirectStdIn or bRedirectStdOut or bRedirectStdErr), \
          "Cannot use %s when redirecting I/O!" % (asWindowSpecificFlags[0],);
    # The output of oStdInPipe is inherited so the application can read from it when we write to the input.
    # The output of oStdInPipe is closed by us after the application is started, as we do not use it and
    # want Windows to clean it up when the application terminates.
    # The input of oStdOutPipe and oStdErrPipe are inherited so the the application can write to them.
    # The input of oStdOutPipe and oStdErrPipe are closed by us after the application is started, as we do
    # not use them and want Windows to clean them up when the application terminates.
    oKernel32 = foLoadKernel32DLL();
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
          odwCreationFlags = DWORD(sum([
            CREATE_SUSPENDED if bSuspended else 0,
            DEBUG_PROCESS if bDebug else 0,
            CREATE_NEW_CONSOLE if bSeparateWindow else 0,
          ]));
          oStartupInfo = STARTUPINFOW();
          oStartupInfo.cb = oStartupInfo.fuGetSize();
          oStartupInfo.lpDesktop = NULL;
          oStartupInfo.lpDesktop = NULL;
          oStartupInfo.dwFlags = STARTF_USESTDHANDLES | (STARTF_USESHOWWINDOW if bSeparateWindow else 0);
          oStartupInfo.wShowWindow = SW_HIDE if bHidden else SW_SHOWMINNOACTIVE if bMinimizedWindow else SW_SHOWMAXIMIZED if bMaximizedWindow else 0;
          oStartupInfo.hStdInput = oStdInPipe.ohOutput if oStdInPipe else oKernel32.GetStdHandle(STD_INPUT_HANDLE);
          oStartupInfo.hStdOutput = oStdOutPipe.ohInput if oStdOutPipe else oKernel32.GetStdHandle(STD_OUTPUT_HANDLE);
          oStartupInfo.hStdError = oStdErrPipe.ohInput if oStdErrPipe else oKernel32.GetStdHandle(STD_ERROR_HANDLE);
          oProcessInformation = PROCESS_INFORMATION();
          opBinaryPath = PCWSTR(sBinaryPath);
          opCommandLine = PWSTR(sCommandLine);
          olpCurrentDirectory = PCWSTR(sWorkingDirectory if sWorkingDirectory else NULL);
          if not oKernel32.CreateProcessW(
            opBinaryPath, # lpApplicationName
            opCommandLine, # lpCommandLine
            NULL, # lpProcessAttributes
            NULL, # lpThreadAttributes
            TRUE, # bInheritHandles
            odwCreationFlags, # dwCreationFlags
            NULL, # lpEnvironment
            olpCurrentDirectory, # lpCurrentDirectory
            oStartupInfo.foCreatePointer(), # lpStartupInfo
            oProcessInformation.foCreatePointer(), # lpProcessInformation
          ):
            fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, %s, NULL, %s, ..., ...)" % \
                (repr(opBinaryPath), repr(opCommandLine), repr(odwCreationFlags), repr(olpCurrentDirectory)));
          # Close all handles that we no longer need:
          if not oKernel32.CloseHandle(oProcessInformation.hThread):
            fThrowLastError("CloseHandle(%s)" % (repr(oProcessInformation.hThread),));
          # Close the ends of the stdin/out/err pipes that we do not use; the child will keep them open until it dies
          # at which point they can be cleaned up because we are not keeping them open ourselves.
          oStdInPipe and oStdInPipe.fClose(bOutput = True); 
          oStdOutPipe and oStdOutPipe.fClose(bInput = True);
          oStdErrPipe and oStdErrPipe.fClose(bInput = True);
          return cConsoleProcess(
            uId = oProcessInformation.dwProcessId.fuGetValue(),
            oStdInPipe = oStdInPipe,
            oStdOutPipe = oStdOutPipe,
            oStdErrPipe = oStdErrPipe,
            ohProcess = oProcessInformation.hProcess,
            uProcessHandleFlags = PROCESS_ALL_ACCESS,
          );
        except:
          oStdErrPipe and oStdErrPipe.fClose();
          raise;
      except:
        oStdOutPipe and oStdOutPipe.fClose();
        raise;
    except:
      oStdInPipe and oStdInPipe.fClose();
      raise;
  
  def __init__(oSelf, uId, oStdInPipe, oStdOutPipe, oStdErrPipe, ohProcess = None, uProcessHandleFlags = None):
    cProcess.__init__(oSelf, uId, ohProcess = ohProcess, uProcessHandleFlags = uProcessHandleFlags);
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
  
  def __del__(oSelf):
    # Make sure all pipes are closed, so as not to cause a handle leak
    try:
      oSelf.fClose();
    except Exception:
      pass;
  
  def fClose(oSelf):
    # This will attemp to close all pipes, even if an exception is thrown when closing one of them. If multiple pipes
    # throw exceptions, all but the last one are ignored.
    try:
      oSelf.oStdInPipe and oSelf.oStdInPipe.fClose();
    finally:
      try:
        oSelf.oStdOutPipe and oSelf.oStdOutPipe.fClose();
      finally:
        oSelf.oStdErrPipe and oSelf.oStdErrPipe.fClose();
  
  def fasGetDetails(oSelf):
    sPiped = " | ".join([s for s in [
        "stdin" if oSelf.oStdInPipe else None,
        "stdout" if oSelf.oStdOutPipe else None,
        "stderr" if oSelf.oStdErrPipe else None,
    ] if s]);
    return cProcess.fasGetDetails(oSelf) + [
      "piped = %s" % sPiped if sPiped else "no I/O piped"
    ];
