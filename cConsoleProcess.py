from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from cPipe import cPipe;
from cProcessInformation import cProcessInformation;
from fsGetErrorMessage import fsGetErrorMessage;

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
  ):
    oStdInPipe = bRedirectStdIn and cPipe(bInheritableInput = False) or None;
    try:
      oStdOutPipe = bRedirectStdOut and cPipe(bInheritableOutput = False) or None;
      try:
        oStdErrPipe = bRedirectStdErr and cPipe(bInheritableOutput = False) or None;
        try:
          sCommandLine = " ".join([
            (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
            for s in [sBinaryPath] + asArguments
          ]);
          uFlags = (bSuspended and CREATE_SUSPENDED or 0);
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
            uFlags, # dwCreationFlags
            NULL, # lpEnvironment
            sWorkingDirectory, # lpCurrentDirectory
            POINTER(oStartupInfo), # lpStartupInfo
            POINTER(oProcessInformation), # lpProcessInformation
          ):
            uCreateProcessError = KERNEL32.GetLastError();
            try:
              oStdErrPipe and oStdErrPipe.fClose();
            finally:
              try:
                oStdOutPipe and oStdOutPipe.fClose();
              finally:
                oStdInPipe and oStdInPipe.fClose();
            assert HRESULT_FROM_WIN32(uCreateProcessError) in [ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME], \
                fsGetErrorMessage("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
                (repr(sBinaryPath), repr(sCommandLine), uFlags, sWorkingDirectory), uCreateProcessError);
            return None;
          try:
            return cConsoleProcess(oProcessInformation.dwProcessId, oStdInPipe, oStdOutPipe, oStdErrPipe);
          finally:
            try:
              assert KERNEL32.CloseHandle(oProcessInformation.hProcess), \
                  fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess,));
            finally:
              assert KERNEL32.CloseHandle(oProcessInformation.hThread), \
                  fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess,));
        except:
          oStdErrPipe and oStdErrPipe.fClose();
          raise;
      except:
        oStdOutPipe and oStdOutPipe.fClose();
        raise;
    except:
      oStdInPipe and oStdInPipe.fClose();
      raise;
  
  def __init__(oSelf, uId, oStdInPipe, oStdOutPipe, oStdErrPipe):
    oSelf.uId = uId;
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
    oSelf.__oInformation = None;
  
  def fClose(oSelf):
    try:
      oSelf.oStdInPipe and oSelf.oStdInPipe.fClose();
    finally:
      try:
        oSelf.oStdOutPipe and oSelf.oStdOutPipe.fClose();
      finally:
        oSelf.oStdErrPipe and oSelf.oStdErrPipe.fClose();

  @property
  def oInformation(oSelf):
    if oSelf.__oInformation is None:
      oSelf.__oInformation = cProcessInformation.foGetForId(oSelf.uId);
    return oSelf.__oInformation;
