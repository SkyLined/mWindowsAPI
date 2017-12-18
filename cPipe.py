from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fThrowError import fThrowError;

guBufferSize = 1;

class cPipe(object):
  def __init__(oSelf, bInheritableInput = True, bInheritableOutput = True):
    oSelf.hInput = HANDLE();
    oSelf.hOutput = HANDLE();
    oSecurityAttributes = SECURITY_ATTRIBUTES();
    oSecurityAttributes.nLength = SIZEOF(oSecurityAttributes);
    oSecurityAttributes.lpSecurityDescriptor = NULL;
    oSecurityAttributes.bInheritHandle = True;
    KERNEL32.CreatePipe(
      POINTER(oSelf.hOutput), # hReadPipe
      POINTER(oSelf.hInput), # hWritePipe
      POINTER(oSecurityAttributes), # lpPipeAttributes
      0, # nSize
    ) or fThrowError("CreatePipe(..., ..., ..., 0)");
    if not bInheritableInput:
      uFlags = HANDLE_FLAG_INHERIT;
      try:
        KERNEL32.SetHandleInformation(oSelf.hInput, uFlags, FALSE) \
            or fThrowError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % \
            (oSelf.hInput.value, uFlags,));
      except:
        oSelf.fClose();
        raise;
    if not bInheritableOutput:
      uFlags = HANDLE_FLAG_INHERIT;
      try:
        KERNEL32.SetHandleInformation(oSelf.hOutput, uFlags, FALSE) \
            or fThrowError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % \
            (oSelf.hOutput.value, uFlags,));
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
          uCloseHandleError = KERNEL32.GetLastError();
          (HRESULT_FROM_WIN32(uCloseHandleError) in [ERROR_INVALID_HANDLE]) \
              or fThrowError("CloseHandle(0x%08X)" % (oSelf.hInput.value,), uCloseHandleError);
    finally:
      if bOutput:
        if not KERNEL32.CloseHandle(oSelf.hOutput):
          uCloseHandleError = KERNEL32.GetLastError();
          (HRESULT_FROM_WIN32(uCloseHandleError) in [ERROR_INVALID_HANDLE]) \
              or fThrowError("CloseHandle(0x%08X)" % (oSelf.hOutput.value,), uCloseHandleError);

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
      uReadFileError = KERNEL32.GetLastError();
      (HRESULT_FROM_WIN32(uReadFileError) in [ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE]) \
          or fThrowError("ReadFile(0x%08X, ..., 0x%X, ..., NULL)" % (oSelf.hOutput.value, SIZEOF(oByte),), \
          uReadFileError);
      raise IOError("Pipe closed");
    assert dwBytesRead.value == 1, \
        "ReadFile(0x%08X, ..., 0x%X, ..., NULL) => read 0x%X bytes" % \
        (oSelf.hOutput.value, SIZEOF(oByte), dwBytesRead.value);
    return oByte.value;

  def fsReadLine(oSelf):
    sData = "";
    while 1:
      try:
        uByte = oSelf.fuReadByte();
      except IOError:
        if sData == "":
          raise;
        break;
      if uByte == 0x0A: # LF
        if sData.endswith("\r"):
          # If EOL was CRLF, strip CR:
          sData = sData[:-1];
        break;
      sData += chr(uByte);
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
      uWriteFileError = KERNEL32.GetLastError();
      (HRESULT_FROM_WIN32(uWriteFileError) in [ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE]) \
          or fThrowError("WriteFile(0x%08X, ..., 0x%X, ..., NULL)" % \
          (oSelf.hInput.value, SIZEOF(oBuffer)), uWriteFileError);
      # The pipe had been closed; throw an IOError.
      raise IOError("Pipe closed");
    assert dwBytesWritten.value == len(sData), \
        "WriteFile(0x%08X, ..., 0x%X, ..., NULL) => wrote 0x%X bytes" % \
        (oSelf.hInput.value, SIZEOF(oBuffer), dwBytesWritten.value);
