import time;
from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

guBufferSize = 1;
gnDefaultConnectTimeoutInSeconds = 1;
gsPipeNameHeader = r"\\.\pipe\\";

class cPipe(object):
  @staticmethod
  def __foSecurityAttributes():
    oSecurityAttributes = SECURITY_ATTRIBUTES();
    oSecurityAttributes.nLength = oSecurityAttributes.fuGetSize();
    oSecurityAttributes.lpSecurityDescriptor = NULL;
    oSecurityAttributes.bInheritHandle = True;
    return oSecurityAttributes;
  
  @classmethod
  def foCreateNamed(cPipe, sName, bReadableInput = True, bWritableOutput = True, bInheritable = True, nConnectTimeoutInSeconds = None):
    assert not sName.startswith(gsPipeNameHeader), \
        "The %s header should not be provided in the name!" % repr(gsPipeNameHeader);
    assert r"\\" not in sName, \
        "The name should not contain backslashes!";
    assert bReadableInput or bWritableOutput, \
        "A pipe must be readable or writable";
  
    odwOpenMode = DWORD(
      PIPE_ACCESS_INBOUND if bReadableInput else 0
      | PIPE_ACCESS_OUTBOUND if bWritableOutput else 0
      | FILE_FLAG_FIRST_PIPE_INSTANCE
      | FILE_FLAG_WRITE_THROUGH # No caching
    );
    odwPipeMode = DWORD(
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
      | PIPE_WAIT # Blocking connect/read/write
      | PIPE_REJECT_REMOTE_CLIENTS # Local connections only for now.
    );
    nDefaultTimeout = long(1000 * (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds));
    ohHandle = oKernel32.CreateNamedPipeW(
      gsPipeNameHeader + sName, # lpName
      odwOpenMode,
      odwPipeMode,
      PIPE_UNLIMITED_INSTANCES, # nMaxInstances
      guBufferSize, # nOutBufferSize
      guBufferSize, # nInBufferSize
      nDefaultTimeout, # nDefaultTimeOut
      cPipe.__foSecurityAttributes().foCreatePointer(), # lpPipeAttributes
    );
    if not fbIsValidHandle(ohHandle):
      fThrowLastError("CreateNamedPipeW(%s, 0x%08X, 0x%08X, PIPE_UNLIMITED_INSTANCES, %d, %d, %d, ...)" % \
          (repr(gsPipeNameHeader + sName), odwOpenMode.value, odwPipeMode.value, guBufferSize, guBufferSize, nDefaultTimeout));
    bSuccess = False;
    try:
      if not bInheritable:
        uFlags = HANDLE_FLAG_INHERIT;
        if not oKernel32.SetHandleInformation(ohHandle, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohHandle.value, uFlags,));
      if not oKernel32.ConnectNamedPipe(ohHandle, NULL):
        if not fbLastErrorIs(ERROR_PIPE_CONNECTED):
          fThrowLastError("ConnectNamedPipe(0x%08X, NULL)" % (ohHandle.value,));
      bSuccess = True;
    finally:
      # Only throw an exception if one isn't already being thrown:
      if not oKernel32.CloseHandle(ohProcess) and bSuccess:
        fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
    return cPipe(sName, ohHandle, ohHandle);
  
  @classmethod
  def foConnectNamed(cPipe, sName, bReadableInput = True, bWritableOutput = True, bInheritable = True, nConnectTimeoutInSeconds = None):
    assert not sName.startswith(gsPipeNameHeader), \
        "The %s header should not be provided in the name!" % repr(gsPipeNameHeader);
    assert r"\\" not in sName, \
        "The name should not contain backslashes!";
    assert bReadableInput or bWritableOutput, \
        "A pipe must be readable or writable";
    odwDesiredAccess = DWORD(
      GENERIC_READ if bReadableInput else 0
      | GENERIC_WRITE if bWritableOutput else 0
    );
    nEndTimeStamp = time.clock() + (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds);
    while 1:
      ohHandle = oKernel32.CreateFileW(
        gsPipeNameHeader + sName, # lpName
        odwDesiredAccess,
        0, # dwShareMode
        cPipe.__foSecurityAttributes().foCreatePointer(), # lpPipeAttributes
        OPEN_EXISTING, # dwCreationDisposition
        0, # dwFlagsAndAttributes
        NULL, # hTemplateFile
      );
      if fbIsValidHandle(ohHandle):
        break;
      if not fbLastErrorIs(ERROR_PIPE_BUSY):
        fThrowLastError("CreateFileW(%s, 0x%08X, 0, ..., OPEN_EXISTING, 0, NULL)" % (repr(gsPipeNameHeader + sName), odwDesiredAccess));
      if time.clock() >= nEndTimeStamp:
        return None;
    odwMode = DWORD(PIPE_READMODE_BYTE | PIPE_WAIT);
    if not oKernel32.SetNamedPipeHandleState(
      ohHandle, # hNamedPipe
      odwMode.foCreatePointer(), # lpMode
      NULL, # lpMaxCollectionCount
      NULL, # lpCollectDataTimeout 
    ):
      fThrowLastError("SetNamedPipeHandleState(%s, 0x%08x, NULL, NULL)" % (ohHandle.value, lpMode));
    return cPipe(sName, ohHandle, ohHandle);
  
  @classmethod
  def foCreate(cPipe, sDescription = None, bInheritableInput = True, bInheritableOutput = True):
    ohInput = HANDLE(); # We write to the pipe's input handle
    ohOutput = HANDLE(); # We read from the pipe's output handle
    if not oKernel32.CreatePipe(
      ohOutput.foCreatePointer(), # hReadPipe
      ohInput.foCreatePointer(), # hWritePipe
      cPipe.__foSecurityAttributes().foCreatePointer(), # lpPipeAttributes
      0, # nSize
    ):
      fThrowLastError("CreatePipe(..., ..., ..., 0)");
    bSuccess = False;
    try:
      uFlags = HANDLE_FLAG_INHERIT;
      if not bInheritableInput:
        if not oKernel32.SetHandleInformation(ohInput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohInput.value, uFlags));
      if not bInheritableOutput:
        if not oKernel32.SetHandleInformation(ohOutput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohOutput.value, uFlags));
      bSuccess = True;
    finally:
      if not bSuccess:
        oKernel32.CloseHandle(ohInput);
        oKernel32.CloseHandle(ohOutput);
    return cPipe(sDescription, ohInput, ohOutput);
  
  def __init__(oSelf, sDescription, ohInput, ohOutput):
    oSelf.sDescription = sDescription; # Just something you can use to remind you of what this pipe does.
    oSelf.__ohInput = ohInput; # We write to the pipe's input handle
    oSelf.__ohOutput = ohOutput; # We read from the pipe's output handle
  
  @property
  def ohInput(oSelf):
    return oSelf.__ohInput;
  @property
  def ohOutput(oSelf):
    return oSelf.__ohOutput;
  
  def fClose(oSelf, bInput = None, bOutput = None):
    if bInput is None and bOutput is None:
      # If nothing is specified, close both. Otherwise close only those for which the value is True-ish.
      bInput = True;
      bOutput = True;
    try:
      if bInput:
        # Named pipes do not have separate input and output handles, so we cannot close them individually.
        assert bOutput or (oSelf.__ohInput != oSelf.__ohOutput), \
            "Cannot close only input on a named pipe!";
        if not oKernel32.CloseHandle(oSelf.__ohInput):
          # It is OK if we cannot close this HANDLE because it is already closed, otherwise we throw an exception.
          if not fbLastErrorIs(ERROR_INVALID_HANDLE):
            fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__ohInput.value,));
    finally:
      # Named pipes do not have separate input and output handles, so we do nnot need to close them individually.
      if bOutput and (not bInput or oSelf.__ohInput != oSelf.__ohOutput):
        if not oKernel32.CloseHandle(oSelf.__ohOutput):
          if not fbLastErrorIs(ERROR_INVALID_HANDLE):
            fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__ohOutput.value,));
  
  def fuReadByte(oSelf):
    oByte = BYTE();
    odwBytesRead = DWORD();
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
    if not oKernel32.ReadFile(
      oSelf.__ohOutput, # hFile # We read from the pipe's output handle
      oByte.foCreatePointer(), # lpBuffer
      oByte.fuGetSize(), # nNumberOfBytesToRead
      odwBytesRead.foCreatePointer(), # lpNumberOfBytesRead
      NULL, # lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("ReadFile(hFile=0x%X, lpBuffer=0x%X, nNumberOfBytesToRead=0x%X, lpNumberOfBytesRead=0x%X, lpOverlapped=NULL)" % \
            (oSelf.__ohOutput.value, oByte.fuGetAddress(), oByte.fuGetSize(), odwBytesRead.fuGetAddress()));
      raise IOError("Pipe closed");
    assert odwBytesRead.value == 1, \
        "ReadFile(hFile=0x%X, lpBuffer=0x%X, nNumberOfBytesToRead=0x%X, lpNumberOfBytesRead=0x%X, lpOverlapped=NULL) => read 0x%X bytes" % \
        (oSelf.__ohOutput.value, oByte.fuGetAddress(), oByte.fuGetSize(), odwBytesRead.fuGetAddress(), odwBytesRead.value);
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
        # If EOL was CRLF, strip CR:
        sData = sData.rstrip("\r");
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
    odwBytesWritten = DWORD(0);
    oBuffer = foCreateBuffer(sData);
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
    if not oKernel32.WriteFile(
      oSelf.__ohInput, # hFile # We write to the pipe's input handle
      oBuffer.foCreatePointer(LPVOID), # lpBuffer
      len(sData), # nNumberOfBytesToWrite (without trailing '\0')
      odwBytesWritten.foCreatePointer(), # lpNumberOfBytesWritten
      NULL, # lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("WriteFile(0x%08X, ..., 0x%X, ..., NULL)" % (oSelf.__ohInput.value, len(sData)));
      # The pipe had been closed; throw an IOError.
      raise IOError("Pipe closed");
    assert odwBytesWritten.value == len(sData), \
        "WriteFile(0x%08X, ..., 0x%X, ..., NULL) => wrote 0x%X bytes" % \
        (oSelf.__ohInput.value, len(sData), odwBytesWritten.value);

  def fWriteLine(oSelf, sData):
    assert "\n" not in sData, \
        "Cannot have '\\n' in data!";
    oSelf.fWriteBytes(sData + "\r\n");