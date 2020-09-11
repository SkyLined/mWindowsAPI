from mWindowsAPI import *;
from oConsole import oConsole;

def fTestPipeHelper(oPipe):
  sWrittenBytes = "test\0test\x7f\x80\xff";
  oPipe.fWriteBytes(sWrittenBytes + "\n");
  sReadBytes = oPipe.fsReadLine();
  assert sReadBytes == sWrittenBytes, \
      "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
  oPipe.fWriteBytes(sWrittenBytes + "\r\n");
  sReadBytes = oPipe.fsReadLine();
  assert sReadBytes == sWrittenBytes, \
      "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
  oPipe.fWriteBytes(sWrittenBytes);
  oPipe.fClose(bInput = True);
  sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
  assert sReadBytes == sWrittenBytes, \
      "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
  sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
  assert sReadBytes == "", \
      "Read %s after closing pipe for write" % repr(sReadBytes);
  oPipe.fClose();
  sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
  assert sReadBytes == "", \
      "Read %s from a completely closed pipe" % repr(sReadBytes);
  try:
    oPipe.fWriteBytes("test");
  except IOError:
    pass;
  else:
    raise AssertionError("Should not be able to write to a closed pipe!");

def fTestPipe():
  # cPipe
  oConsole.fOutput("* Testing cPipe...");
  fTestPipeHelper(cPipe.foCreate());
  oConsole.fOutput("  * Testing cPipe with non-inheritable handles...");
  fTestPipeHelper(cPipe.foCreate(bInheritableInput = False, bInheritableOutput = False));
  
