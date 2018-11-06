import time;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;

guBufferSize = 1;
gnDefaultConnectTimeoutInSeconds = 1;
gsPipeNameHeader = r"\\.\pipe\\";

class cPipe(object):
  @staticmethod
  def __foSecurityAttributes():
    oSecurityAttributes = SECURITY_ATTRIBUTES();
    oSecurityAttributes.nLength = fuSizeOf(oSecurityAttributes);
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
  
    dwOpenMode = DWORD(
      PIPE_ACCESS_INBOUND if bReadableInput else 0
      | PIPE_ACCESS_OUTBOUND if bWritableOutput else 0
      | FILE_FLAG_FIRST_PIPE_INSTANCE
      | FILE_FLAG_WRITE_THROUGH # No caching
    );
    dwPipeMode = DWORD(
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
      | PIPE_WAIT # Blocking connect/read/write
      | PIPE_REJECT_REMOTE_CLIENTS # Local connections only for now.
    );
    nDefaultTimeout = long(1000 * (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds));
    hHandle = KERNEL32.CreateNamedPipeW(
      gsPipeNameHeader + sName, # lpName
      dwOpenMode,
      dwPipeMode,
      PIPE_UNLIMITED_INSTANCES, # nMaxInstances
      guBufferSize, # nOutBufferSize
      guBufferSize, # nInBufferSize
      nDefaultTimeout, # nDefaultTimeOut
      POINTER(cPipe.__foSecurityAttributes()), # lpPipeAttributes
    );
    if not fbIsValidHandle(hHandle):
      fThrowLastError("CreateNamedPipeW(%s, 0x%08X, 0x%08X, PIPE_UNLIMITED_INSTANCES, %d, %d, %d, ...)" % \
          (repr(gsPipeNameHeader + sName), dwOpenMode, dwPipeMode, guBufferSize, guBufferSize, nDefaultTimeout));
    bSuccess = False;
    try:
      if not bInheritable:
        uFlags = HANDLE_FLAG_INHERIT;
        if not KERNEL32.SetHandleInformation(hHandle, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (hInput.value, uFlags,));
      if not KERNEL32.ConnectNamedPipe(hHandle, NULL):
        if not fbLastErrorIs(ERROR_PIPE_CONNECTED):
          fThrowLastError("ConnectNamedPipe(0x%08X, NULL)" % (hHandle.value,));
      bSuccess = True;
    finally:
      if not bSuccess:
        KERNEL32.CloseHandle(hHandle);
    return cPipe(sName, hHandle, hHandle);
  
  @classmethod
  def foConnectNamed(cPipe, sName, bReadableInput = True, bWritableOutput = True, bInheritable = True, nConnectTimeoutInSeconds = None):
    assert not sName.startswith(gsPipeNameHeader), \
        "The %s header should not be provided in the name!" % repr(gsPipeNameHeader);
    assert r"\\" not in sName, \
        "The name should not contain backslashes!";
    assert bReadableInput or bWritableOutput, \
        "A pipe must be readable or writable";
    dwDesiredAccess = DWORD(
      GENERIC_READ if bReadableInput else 0
      | GENERIC_WRITE if bWritableOutput else 0
    );
    nEndTimeStamp = time.clock() + (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds);
    while 1:
      hHandle = KERNEL32.CreateFileW(
        gsPipeNameHeader + sName, # lpName
        dwDesiredAccess,
        0, # dwShareMode
        POINTER(cPipe.__foSecurityAttributes()), # lpPipeAttributes
        DWORD(OPEN_EXISTING), # dwCreationDisposition
        0, # dwFlagsAndAttributes
        NULL, # hTemplateFile
      );
      if hHandle is not INVALID_HANDLE_VALUE:
        break;
      if not fbLastErrorIs(ERROR_PIPE_BUSY):
        fThrowLastError("CreateFileW(%s, 0x%08X, 0, ..., OPEN_EXISTING, 0, NULL)" % (repr(gsPipeNameHeader + sName), dwDesiredAccess));
      if time.clock() >= nEndTimeStamp:
        return None;
    dwMode = DWORD(PIPE_READMODE_BYTE | PIPE_WAIT);
    if not KERNEL32.SetNamedPipeHandleState(
      hHandle, # hNamedPipe
      POINTER(dwMode), # lpMode
      NULL, # lpMaxCollectionCount
      NULL, # lpCollectDataTimeout 
    ):
      fThrowLastError("SetNamedPipeHandleState(%s, 0x%08x, NULL, NULL)" % (hHandle.value, lpMode));
    return cPipe(sName, hHandle, hHandle);
  
  @classmethod
  def foCreate(cPipe, sDescription = None, bInheritableInput = True, bInheritableOutput = True):
    hInput = HANDLE(); # We write to the pipe's input handle
    hOutput = HANDLE(); # We read from the pipe's output handle
    if not KERNEL32.CreatePipe(
      POINTER(hOutput), # hReadPipe
      POINTER(hInput), # hWritePipe
      POINTER(cPipe.__foSecurityAttributes()), # lpPipeAttributes
      0, # nSize
    ):
      fThrowLastError("CreatePipe(..., ..., ..., 0)");
    bSuccess = False;
    try:
      uFlags = HANDLE_FLAG_INHERIT;
      if not bInheritableInput:
        if not KERNEL32.SetHandleInformation(hInput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (hInput.value, uFlags));
      if not bInheritableOutput:
        if not KERNEL32.SetHandleInformation(hOutput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (hOutput.value, uFlags));
      bSuccess = True;
    finally:
      if not bSuccess:
        KERNEL32.CloseHandle(hInput);
        KERNEL32.CloseHandle(hOutput);
    return cPipe(sDescription, hInput, hOutput);
  
  def __init__(oSelf, sDescription, hInput, hOutput):
    oSelf.sDescription = sDescription; # Just something you can use to remind you of what this pipe does.
    oSelf.__hInput = hInput; # We write to the pipe's input handle
    oSelf.__hOutput = hOutput; # We read from the pipe's output handle
  
  @property
  def hInput(oSelf):
    return oSelf.__hInput;
  @property
  def hOutput(oSelf):
    return oSelf.__hOutput;
  
  def fClose(oSelf, bInput = None, bOutput = None):
    if bInput is None and bOutput is None:
      # If nothing is specified, close both. Otherwise close only those for which the value is True-ish.
      bInput = True;
      bOutput = True;
    try:
      if bInput:
        # Named pipes do not have separate input and output handles, so we cannot close them individually.
        assert bOutput or (oSelf.__hInput != oSelf.__hOutput), \
            "Cannot close only input on a named pipe!";
        if not KERNEL32.CloseHandle(oSelf.__hInput):
          # It is OK if we cannot close this HANDLE because it is already closed, otherwise we throw an exception.
          if not fbLastErrorIs(ERROR_INVALID_HANDLE):
            fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__hInput.value,));
    finally:
      # Named pipes do not have separate input and output handles, so we do nnot need to close them individually.
      if bOutput and (not bInput or oSelf.__hInput != oSelf.__hOutput):
        if not KERNEL32.CloseHandle(oSelf.__hOutput):
          if not fbLastErrorIs(ERROR_INVALID_HANDLE):
            fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__hOutput.value,));
  
  def fuReadByte(oSelf):
    oByte = BYTE();
    dwBytesRead = DWORD();
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
    if not KERNEL32.ReadFile(
      oSelf.__hOutput, # hFile # We read from the pipe's output handle
      POINTER(oByte), # lpBuffer
      fuSizeOf(oByte), # nNumberOfBytesToRead
      POINTER(dwBytesRead), # lpNumberOfBytesRead
      NULL, # lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("ReadFile(0x%08X, ..., 0x%X, ..., NULL)" % (oSelf.__hOutput.value, fuSizeOf(oByte),));
      raise IOError("Pipe closed");
    assert dwBytesRead.value == 1, \
        "ReadFile(0x%08X, ..., 0x%X, ..., NULL) => read 0x%X bytes" % \
        (oSelf.__hOutput.value, fuSizeOf(oByte), dwBytesRead.value);
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
      oSelf.__hInput, # hFile # We write to the pipe's input handle
      POINTER(oBuffer), # lpBuffer
      len(sData), # nNumberOfBytesToWrite (without trailing '\0')
      POINTER(dwBytesWritten), # lpNumberOfBytesWritten
      NULL, # lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("WriteFile(0x%08X, ..., 0x%X, ..., NULL)" % (oSelf.__hInput.value, fuSizeOf(oBuffer)));
      # The pipe had been closed; throw an IOError.
      raise IOError("Pipe closed");
    assert dwBytesWritten.value == len(sData), \
        "WriteFile(0x%08X, ..., 0x%X, ..., NULL) => wrote 0x%X bytes" % \
        (oSelf.__hInput.value, fuSizeOf(oBuffer), dwBytesWritten.value);

  def fWriteLine(oSelf, sData):
    assert "\n" not in sData, \
        "Cannot have '\\n' in data!";
    oSelf.fWriteBytes(sData + "\r\n");