from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from cPipe import cPipe;

class cConsoleProcess(object):
  @staticmethod
  def foCreateForBinaryPathAndArguments(sBinaryPath, asArguments, sWorkingDirectory = None, bSuspended = False):
    oStdInPipe = cPipe(bInheritableInput = False); # The output is inheritted and used as stdin, the input is sent by us
    try:
      oStdOutPipe = cPipe(bInheritableOutput = False); # The input is inheritted and used as stdout, the output is read by us
      try:
        oStdErrPipe = cPipe(bInheritableOutput = False); # The input is inheritted and used as stderr, the output is read by us.
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
          oStartupInfo.hStdInput = oStdInPipe.hOutput;
          oStartupInfo.hStdOutput = oStdOutPipe.hInput;
          oStartupInfo.hStdError = oStdErrPipe.hInput;
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
            uError = KERNEL32.GetLastError();
            try:
              oStdErrPipe.fClose();
            finally:
              try:
                oStdOutPipe.fClose();
              finally:
                oStdInPipe.fClose();
            assert HRESULT_FROM_WIN32(uError) in [ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME], \
                "CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...) => Error 0x%08X." % \
                (repr(sBinaryPath), repr(sCommandLine), uFlags, sWorkingDirectory, uError);
            return None;
          try:
            return cConsoleProcess(oProcessInformation.dwProcessId, oStdInPipe, oStdOutPipe, oStdErrPipe);
          finally:
            try:
              assert KERNEL32.CloseHandle(oProcessInformation.hProcess), \
                  "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
            finally:
              assert KERNEL32.CloseHandle(oProcessInformation.hThread), \
                  "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
        except:
          oStdErrPipe.fClose();
          raise;
      except:
        oStdOutPipe.fClose();
        raise;
    except:
      oStdInPipe.fClose();
      raise;
  
  def __init__(oSelf, uId, oStdInPipe, oStdOutPipe, oStdErrPipe):
    oSelf.uId = uId;
    oSelf.oStdInPipe = oStdInPipe;
    oSelf.oStdOutPipe = oStdOutPipe;
    oSelf.oStdErrPipe = oStdErrPipe;
  
  def fClose(oSelf):
    try:
      oSelf.oStdInPipe.fClose();
    finally:
      try:
        oSelf.oStdOutPipe.fClose();
      finally:
        oSelf.oStdErrPipe.fClose();
              