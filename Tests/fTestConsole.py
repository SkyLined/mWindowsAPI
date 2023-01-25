from mConsole import oConsole;
from mWindowsAPI import fThrowLastError;
from mWindowsSDK import \
    CONSOLE_SCREEN_BUFFER_INFO, \
    STD_OUTPUT_HANDLE;

def fTestConsole():
  # Test console functions
  from mWindowsSDK.mKernel32 import oKernel32DLL;
  oConsole.fOutput("* Testing oKernel32 console functions...");
  ohStdOut = oKernel32DLL.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  if not oKernel32DLL.GetConsoleScreenBufferInfo(ohStdOut, oConsoleScreenBufferInfo.foCreatePointer()):
    fThrowLastError("GetConsoleScreenBufferInfo(0x%08X, 0x%X)" % (ohStdOut.value, oConsoleScreenBufferInfo.fuGetAddress()));
  oConsole.fOutput("  Console buffer size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwSize.X, oConsoleScreenBufferInfo.dwSize.Y));
  oConsole.fOutput("  Console window size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwMaximumWindowSize.X, oConsoleScreenBufferInfo.dwMaximumWindowSize.Y));
  uOriginalColor = oConsoleScreenBufferInfo.wAttributes & 0xFF;
  uTestColor = (uOriginalColor & 0xF0) | 0x0A; # Bright green foreground, keep same background.
  if not oKernel32DLL.SetConsoleTextAttribute(ohStdOut, uTestColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uTestColor));
  oConsole.fOutput("  * This should be green.");
  if not oKernel32DLL.SetConsoleTextAttribute(ohStdOut, uOriginalColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uOriginalColor));
  
