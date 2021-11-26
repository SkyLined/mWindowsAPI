import time;

from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;

from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = fShowDebugOutput = lambda x: x; # NOP

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
  @ShowDebugOutput
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
    nDefaultTimeout = int(1000 * (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds));
    ohHandle = oKernel32DLL.CreateNamedPipeW(
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
        if not oKernel32DLL.SetHandleInformation(ohHandle, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohHandle.value, uFlags,));
      if not oKernel32DLL.ConnectNamedPipe(ohHandle, NULL):
        if not fbLastErrorIs(ERROR_PIPE_CONNECTED):
          fThrowLastError("ConnectNamedPipe(0x%08X, NULL)" % (ohHandle.value,));
      bSuccess = True;
    finally:
      # Only throw an exception if one isn't already being thrown:
      if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
        fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
    return cPipe(sName, ohHandle, ohHandle);
  
  @classmethod
  @ShowDebugOutput
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
    nEndTimeStamp = time.time() + (nConnectTimeoutInSeconds if nConnectTimeoutInSeconds is not None else gnDefaultConnectTimeoutInSeconds);
    while 1:
      ohHandle = oKernel32DLL.CreateFileW(
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
      if time.time() >= nEndTimeStamp:
        return None;
    odwMode = DWORD(PIPE_READMODE_BYTE | PIPE_WAIT);
    if not oKernel32DLL.SetNamedPipeHandleState(
      ohHandle, # hNamedPipe
      odwMode.foCreatePointer(), # lpMode
      NULL, # lpMaxCollectionCount
      NULL, # lpCollectDataTimeout 
    ):
      fThrowLastError("SetNamedPipeHandleState(%s, 0x%08x, NULL, NULL)" % (ohHandle.value, lpMode));
    return cPipe(sName, ohHandle, ohHandle);
  
  @classmethod
  @ShowDebugOutput
  def foCreate(cPipe, sDescription = None, bInheritableInput = True, bInheritableOutput = True):
    ohInput = HANDLE(); # We write to the pipe's input handle
    ohOutput = HANDLE(); # We read from the pipe's output handle
    if not oKernel32DLL.CreatePipe(
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
        if not oKernel32DLL.SetHandleInformation(ohInput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohInput.value, uFlags));
      if not bInheritableOutput:
        if not oKernel32DLL.SetHandleInformation(ohOutput, uFlags, FALSE):
          fThrowLastError("SetHandleInformation(0x%08X, 0x%08X, FALSE)" % (ohOutput.value, uFlags));
      bSuccess = True;
    finally:
      if not bSuccess:
        oKernel32DLL.CloseHandle(ohInput);
        oKernel32DLL.CloseHandle(ohOutput);
    return cPipe(sDescription, ohInput, ohOutput);
  
  @ShowDebugOutput
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
  
  @property
  def bClosed(oSelf):
    return oSelf.__ohInput is INVALID_HANDLE_VALUE and oSelf.__ohOutput is INVALID_HANDLE_VALUE;
  @property
  def bClosedForReading(oSelf):
    return oSelf.__ohOutput is INVALID_HANDLE_VALUE;
  @property
  def bClosedForWriting(oSelf):
    return oSelf.__ohInput is INVALID_HANDLE_VALUE;
  
  @ShowDebugOutput
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
        if oSelf.__ohInput is not INVALID_HANDLE_VALUE:
          fShowDebugOutput("Closing pipe input (writing will no longer be possible)");
          if not oKernel32DLL.CloseHandle(oSelf.__ohInput):
            # It is OK if we cannot close this HANDLE because it is already closed, otherwise we throw an exception.
            if not fbLastErrorIs(ERROR_INVALID_HANDLE):
              fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__ohInput.value,));
          oSelf.__ohInput = INVALID_HANDLE_VALUE;
    finally:
      # Named pipes do not have separate input and output handles, so we do nnot need to close them individually.
      if bOutput and (not bInput or oSelf.__ohInput != oSelf.__ohOutput):
        if oSelf.__ohOutput is not INVALID_HANDLE_VALUE:
          fShowDebugOutput("Closing pipe output (reading will no longer be possible)");
          if not oKernel32DLL.CloseHandle(oSelf.__ohOutput):
            if not fbLastErrorIs(ERROR_INVALID_HANDLE):
              fThrowLastError("CloseHandle(0x%08X)" % (oSelf.__ohOutput.value,));
          oSelf.__ohOutput = INVALID_HANDLE_VALUE;
  
  # fu0ReadByte shows debug output. There's also a version without debug output for internal use. This second version
  # may be called repeatedly to read multiple bytes, and having it produce debug output would not be useful.
  # @ShowDebugOutput This gets call A LOT!
  def fu0ReadByte(oSelf):
    return oSelf.__fu0ReadByte();
  def __fu0ReadByte(oSelf):
    oByte = BYTE();
    odwBytesRead = DWORD();
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
    if not oKernel32DLL.ReadFile(
      oSelf.__ohOutput,                         # HANDLE       hFile    # We read from the pipe's output handle
      oByte.foCreatePointer().foCastTo(LPVOID), # LPVOID       lpBuffer
      oByte.fuGetSize(),                        # DWORD        nNumberOfBytesToRead
      odwBytesRead.foCreatePointer(),           # LPDWORD      lpNumberOfBytesRead
      NULL,                                     # LPOVERLAPPED lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("ReadFile(hFile=%s, lpBuffer=0x%X, nNumberOfBytesToRead=0x%X, lpNumberOfBytesRead=0x%X, lpOverlapped=NULL)" % \
            (repr(oSelf.__ohOutput), oByte.fuGetAddress(), oByte.fuGetSize(), odwBytesRead.fuGetAddress()));
      return None;
    assert odwBytesRead.fuGetValue() == 1, \
        "ReadFile(hFile=%s, lpBuffer=0x%X, nNumberOfBytesToRead=0x%X, lpNumberOfBytesRead=0x%X, lpOverlapped=NULL) => read 0x%X bytes" % \
        (repr(oSelf.__ohOutput), oByte.fuGetAddress(), oByte.fuGetSize(), odwBytesRead.fuGetAddress(), odwBytesRead);
    return oByte.fuGetValue();
  
  @ShowDebugOutput
  def fsbReadBytes(oSelf, uNumberOfBytes = None):
    auData = [];
    while uNumberOfBytes is None or len(auData) < uNumberOfBytes:
      u0Byte = oSelf.__fu0ReadByte();
      if u0Byte is None:
        break;
      auData.append(u0Byte);
    return bytes(auData);
  
  @ShowDebugOutput
  def fsb0ReadLine(oSelf):
    auData = [];
    while True:
      u0Byte = oSelf.__fu0ReadByte();
      if u0Byte is None or u0Byte == 0x0A: # EOL = LF
        break;
      if u0Byte != 0x0D: # ignore CR
        auData.append(u0Byte);
    if u0Byte is None and len(auData) == 0:
      return None;
    return bytes(auData);
  
  @ShowDebugOutput
  def fsRead(oSelf, uNumberOfChars = None):
    sbData = b"";
    sData = "";
    # Read until:
    # - we have read the number of chars the caller wants,
    # - or we have read 4 bytes and are unable to decode them as a Unicode character
    while (uNumberOfChars is None or len(sData) < uNumberOfChars) and len(sbData) < 4:
      u0Byte = oSelf.__fu0ReadByte();
      if u0Byte is None:
        break;
      sbData += bytes((u0Byte,));
      try:
        sData += str(sbData, 'utf-8');
      except UnicodeDecodeError:
        # We may have read some but not all of the bytes that encode a Unicode char, so this
        # exception can be expected in some cases.
        pass;
      else:
        sbData = b"";
    # If there is anything left in the buffer, make sure we parse it and add it to the data.
    # If the remote has sent us invalid utf-8 encoded data, this will throw a UnicodeDecodeError
    sData += str(sbData, 'utf-8');
    return sData;
  
  @ShowDebugOutput
  def fs0ReadLine(oSelf):
    sbData = b""; # stores utf-8 encoded character bytes read from the pipe
    sData = ""; # stores characters decoded from the utf-8 bytes.
    # Read until we have read 4 bytes and are unable to decode them as a Unicode character
    while len(sbData) < 4:
      u0Byte = oSelf.__fu0ReadByte();
      if u0Byte is None: # pipe has been closed
        if len(sData) == 0 and len(sbData) == 0: # nothing received: return None;
          return None;
        break; # return whatever we received so far.
      sbData += bytes((u0Byte,));
      try:
        sChar = str(sbData, 'utf-8');
      except UnicodeDecodeError:
        # We may have read some but not all of the bytes that encode a Unicode char, so this
        # exception can be expected in some cases.
        pass;
      else:
        sbData = b""; # reset utf-8 buffer.
        if sChar == "\n": # newline: stop reading.
          break;
        sData += sChar # add character to data.
    # If there is anything left in the buffer, make sure we parse it and add it to the data.
    # If the remote has sent us invalid utf-8 encoded data, this will throw a UnicodeDecodeError
    sData += str(sbData, 'utf-8');
    return sData.rstrip("\r"); # If EOF was CRLF, strip CR:
  
  @ShowDebugOutput
  def fWriteBytes(oSelf, sbData):
    assert isinstance(sbData, bytes), \
        "sbData must be bytes, not %s (%s)" % (repr(sbData.__class__), repr(sbData));
    odwBytesWritten = DWORD(0);
    opBuffer = PCHAR(sbData).foCastTo(LPVOID);
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
    if not oKernel32DLL.WriteFile(
      oSelf.__ohInput, # hFile # We write to the pipe's input handle
      opBuffer, # lpBuffer
      len(sbData), # nNumberOfBytesToWrite (without trailing '\0')
      odwBytesWritten.foCreatePointer(), # lpNumberOfBytesWritten
      NULL, # lpOverlapped
    ):
      if not fbLastErrorIs(ERROR_INVALID_HANDLE, ERROR_BROKEN_PIPE):
        fThrowLastError("WriteFile(0x%08X, ..., 0x%X, ..., NULL)" % (oSelf.__ohInput.value, len(sbData)));
      # The pipe had been closed; throw an IOError.
      raise IOError("Pipe closed");
    assert odwBytesWritten.value == len(sbData), \
        "WriteFile(0x%08X, ..., 0x%X, ..., NULL) => wrote 0x%X bytes" % \
        (oSelf.__ohInput.value, len(sbData), odwBytesWritten.value);
  
  @ShowDebugOutput
  def fWrite(oSelf, sData):
    oSelf.fWriteBytes(bytes(sData, "utf-8"));
  
  @ShowDebugOutput
  def fWriteLine(oSelf, sData):
    assert "\n" not in sData, \
        "Cannot have '\\n' in data!";
    oSelf.fWriteBytes(bytes(sData, "utf-8") + b"\r\n");
  
