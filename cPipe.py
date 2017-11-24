from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;

guBufferSize = 1;

class cPipe(object):
  def __init__(oSelf, bInheritableInput = True, bInheritableOutput = True):
    oSelf.hInput = HANDLE();
    oSelf.hOutput = HANDLE();
    oSecurityAttributes = SECURITY_ATTRIBUTES();
    oSecurityAttributes.nLength = SIZEOF(oSecurityAttributes);
    oSecurityAttributes.lpSecurityDescriptor = NULL;
    oSecurityAttributes.bInheritHandle = True;
    assert KERNEL32.CreatePipe(
      POINTER(oSelf.hOutput), # hReadPipe
      POINTER(oSelf.hInput), # hWritePipe
      POINTER(oSecurityAttributes), # lpPipeAttributes
      0, # nSize
    ), "CreatePipe(..., ..., ..., 0) => Error 0x%08X" % KERNEL32.GetLastError();
    if not bInheritableInput:
      try:
        assert KERNEL32.SetHandleInformation(oSelf.hInput, HANDLE_FLAG_INHERIT, FALSE), \
            "SetHandleInformation(0x%08X, HANDLE_FLAG_INHERIT, FALSE) => Error 0x%08X" % \
            (oSelf.hInput.value, KERNEL32.GetLastError());
      except:
        oSelf.fClose();
        raise;
    if not bInheritableOutput:
      try:
        assert KERNEL32.SetHandleInformation(oSelf.hOutput, HANDLE_FLAG_INHERIT, FALSE), \
            "SetHandleInformation(0x%08X, HANDLE_FLAG_INHERIT, FALSE) => Error 0x%08X" % \
            (oSelf.hOutput.value, KERNEL32.GetLastError());
      except:
        oSelf.fClose();
        raise;
  
  def fClose(oSelf, bInput = None, bOutput = None):
    if bInput is None and bOutput is None:
      # If nothing is specified, close both. Otherwise close only those for which the value is True-ish.
      bInput = True;
      bOutput = True;
    try:
      if bInput:
        if not KERNEL32.CloseHandle(oSelf.hInput):
          # It is OK if we cannot close this HANDLE because it is already closed, otherwise we throw an exception.
          uError = KERNEL32.GetLastError();
          assert HRESULT_FROM_WIN32(uError) in [ERROR_INVALID_HANDLE], \
              "CloseHandle(0x%08X) => Error 0x%08X" % (oSelf.hInput.value, uError);
    finally:
      if bOutput:
        if not KERNEL32.CloseHandle(oSelf.hOutput):
          uError = KERNEL32.GetLastError();
          assert HRESULT_FROM_WIN32(uError) in [ERROR_INVALID_HANDLE], \
              "CloseHandle(0x%08X) => Error 0x%08X" % (oSelf.hOutput.value, uError);

  def fuReadByte(oSelf):
    oByte = BYTE();
    dwBytesRead = DWORD();
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
    if not KERNEL32.ReadFile(
      oSelf.hOutput, # hFile
      POINTER(oByte), # lpBuffer
      SIZEOF(oByte), # nNumberOfBytesToRead
      POINTER(dwBytesRead), # lpNumberOfBytesRead
      NULL, # lpOverlapped
    ):
      uLastError = KERNEL32.GetLastError();
      assert HRESULT_FROM_WIN32(uLastError) in [ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE], \
          "ReadFile(0x%08X, ..., 0x%X, ..., NULL) => Error 0x%08X" % \
          (oSelf.hOutput.value, SIZEOF(oByte), KERNEL32.GetLastError());
      raise IOError("Pipe closed");
    assert dwBytesRead.value == 1, \
        "Read %d bytes instead of 1" % dwBytesRead.value;
    return oByte.value;

  def fsReadLine(oSelf):
    sData = "";
    while 1:
      try:
        sChar = chr(oSelf.fuReadByte());
      except IOError:
        if sData == "":
          raise;
        break;
      if sChar == "\n":
        break;
      sData += sChar;
    if sData[-1] == "\r":
      # If EOL was CRLF, strip CR:
      sData = sData[:-1];
    return sData;
  
  def fsReadBytes(oSelf, uNumberOfBytes = None):
    sData = "";
    while uNumberOfBytes is None or len(sData) < uNumberOfBytes:
      try:
        sData += chr(oSelf.fuReadByte());
      except IOError:
        break;
    return sData;
  
  def fWriteBytes(oSelf, sData):
    oBuffer = STR(sData); 
    dwBytesWritten = DWORD(0);
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
    if not KERNEL32.WriteFile(
      oSelf.hInput, # hFile
      POINTER(oBuffer), # lpBuffer
      len(sData), # nNumberOfBytesToWrite (without trailing '\0')
      POINTER(dwBytesWritten), # lpNumberOfBytesWritten
      NULL, # lpOverlapped
    ):
      uLastError = KERNEL32.GetLastError();
      assert HRESULT_FROM_WIN32(uLastError) in [ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE], \
          "WriteFile(0x%08X, ..., 0x%X, ..., NULL) => Error 0x%08X" % \
          (oSelf.hInput.value, SIZEOF(oBuffer), KERNEL32.GetLastError());
      # The pipe had been closed; throw an IOError.
      raise IOError("Pipe closed");
    assert dwBytesWritten.value == len(sData), \
        "Expected to write %d bytes, but wrote %d." % (len(sData), dwBytesWritten.value);
