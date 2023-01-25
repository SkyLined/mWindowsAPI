from mConsole import oConsole;
from mWindowsAPI import cPipe;

def fTestPipeHelper(oPipe):
  # Write a line with LF and a line with crlf, then read both back
  oConsole.fOutput("  * Write/read lines...");
  sWrittenData = "test\0test\x7f\x80\xff\n" "test2\r\n";
  asExpectedReadData = ["test\0test\x7f\x80\xff", "test2"];
  oPipe.fWrite(sWrittenData);
  as0ReadData = [];
  while len(as0ReadData) < len(asExpectedReadData):
    s0ReadData = oPipe.fs0ReadLine();
    as0ReadData.append(s0ReadData);
    if s0ReadData is None:
      break;
  assert as0ReadData == asExpectedReadData, \
      "Expected to read data %s, but got %s" % (repr(asExpectedReadData), repr(as0ReadData));
  
  oConsole.fOutput("  * Write/read bytes and close...");
  # Write bytes, read them back
  sbWrittenBytes = b"test\0test\x7f\x80\xff";
  oPipe.fWriteBytes(sbWrittenBytes);
  sbReadBytes = oPipe.fsbReadBytes(len(sbWrittenBytes));
  assert sbReadBytes == sbWrittenBytes, \
      "Expected %s, got %s" % (repr(sbWrittenBytes), repr(sbReadBytes));
  # Write bytes, close input pipe, read them back
  oPipe.fWriteBytes(sbWrittenBytes);
  oPipe.fClose(bInput = True);
  sbReadBytes = oPipe.fsbReadBytes(len(sbWrittenBytes));
  assert sbReadBytes == sbWrittenBytes, \
      "Expected %s, got %s" % (repr(sbWrittenBytes), repr(sbReadBytes));
  # Make sure there's no more data in the pipe.
  sbReadBytes = oPipe.fsbReadBytes(len(sbWrittenBytes));
  assert sbReadBytes == b"", \
      "Read %s after closing pipe for write" % repr(sbReadBytes);
  oPipe.fClose();
  sbReadBytes = oPipe.fsbReadBytes();
  assert sbReadBytes == b"", \
      "Read %s from a completely closed pipe" % repr(sbReadBytes);
  # Make sure we cannot write to the pipe anymore
  try:
    oPipe.fWrite("test");
  except IOError:
    pass;
  else:
    raise AssertionError("Should not be able to write to a closed pipe!");

def fTestPipe():
  # cPipe
  oConsole.fOutput("* Testing cPipe...");
  fTestPipeHelper(cPipe.foCreate());
  oConsole.fOutput("* Testing cPipe with non-inheritable handles...");
  fTestPipeHelper(cPipe.foCreate(bInheritableInput = False, bInheritableOutput = False));
  
