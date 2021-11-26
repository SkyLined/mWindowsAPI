from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;

from .cPipe import cPipe;
from .cProcess import cProcess;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = fShowDebugOutput = lambda x: x; # NOP

class cConsoleProcess(cProcess):
  @staticmethod
  def foGetForId(uProcessId):
    # Overwrite cProcess.foGetForId, as we cannot get the stdi/o streams for an existing process.
    raise NotImplementedError("This is not possible for console processes");
  @staticmethod
  @ShowDebugOutput
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
    bTerminateAutomatically = True,
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
          fShowDebugOutput("sBinaryPath = %s" % repr(sBinaryPath));
          fShowDebugOutput("sCommandLine = %s" % repr(sCommandLine));
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
          oStartupInfo.hStdInput = oStdInPipe.ohOutput if oStdInPipe else oKernel32DLL.GetStdHandle(STD_INPUT_HANDLE);
          oStartupInfo.hStdOutput = oStdOutPipe.ohInput if oStdOutPipe else oKernel32DLL.GetStdHandle(STD_OUTPUT_HANDLE);
          oStartupInfo.hStdError = oStdErrPipe.ohInput if oStdErrPipe else oKernel32DLL.GetStdHandle(STD_ERROR_HANDLE);
          oProcessInformation = PROCESS_INFORMATION();
          opBinaryPath = PCWSTR(sBinaryPath);
          opCommandLine = PWSTR(sCommandLine);
          olpCurrentDirectory = PCWSTR(sWorkingDirectory if sWorkingDirectory else NULL);
          if not oKernel32DLL.CreateProcessW(
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
          if not oKernel32DLL.CloseHandle(oProcessInformation.hThread):
            fThrowLastError("CloseHandle(%s)" % (repr(oProcessInformation.hThread),));
          # Close the ends of the stdin/out/err pipes that we do not use; the child will keep them open until it dies
          # at which point they can be cleaned up because we are not keeping them open ourselves.
          oStdInPipe and oStdInPipe.fClose(bOutput = True); 
          oStdOutPipe and oStdOutPipe.fClose(bInput = True);
          oStdErrPipe and oStdErrPipe.fClose(bInput = True);
          uProcessId = oProcessInformation.dwProcessId.fuGetValue();
          fShowDebugOutput("Process id = %d/0x%X" % (uProcessId, uProcessId));
          return cConsoleProcess(
            uId = uProcessId,
            oStdInPipe = oStdInPipe,
            oStdOutPipe = oStdOutPipe,
            oStdErrPipe = oStdErrPipe,
            ohProcess = oProcessInformation.hProcess,
            uProcessHandleFlags = PROCESS_ALL_ACCESS,
            bTerminateAutomatically = bTerminateAutomatically,
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
  
  @ShowDebugOutput
  def __init__(oSelf, uId, oStdInPipe, oStdOutPipe, oStdErrPipe, ohProcess = None, uProcessHandleFlags = None, bTerminateAutomatically = True):
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
    cProcess.__init__(oSelf, uId, ohProcess = ohProcess, uProcessHandleFlags = uProcessHandleFlags, bTerminateAutomatically = bTerminateAutomatically);
  
  def __del__(oSelf):
    # Make sure all pipes are closed, so as not to cause a handle leak
    try:
      oSelf.oStdInPipe.fClose();
    except:
      pass;
      try:
        oSelf.oStdOutPipe and oSelf.oStdOutPipe.fClose();
      finally:
        oSelf.oStdErrPipe and oSelf.oStdErrPipe.fClose();
  
  @ShowDebugOutput
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
