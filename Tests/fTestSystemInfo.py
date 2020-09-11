from mWindowsAPI import *;
from mWindowsSDK import SECURITY_MANDATORY_MEDIUM_RID;
from oConsole import oConsole;

def fTestSystemInfo():
  oConsole.fOutput("* Testing system info...");
  oConsole.fOutput("  * fsGetPythonISA() = %s" % fsGetPythonISA());
  oConsole.fOutput("  * oSystemInfo...");
  oConsole.fOutput("    | OS:                      %s" %  oSystemInfo.sOSFullDetails);
  oConsole.fOutput("    | Processors:              %d" % oSystemInfo.uNumberOfProcessors);
  oConsole.fOutput("    | Address range:           0x%08X - 0x%08X" % (oSystemInfo.uMinimumApplicationAddress, oSystemInfo.uMaximumApplicationAddress));
  oConsole.fOutput("    | Page size:               0x%X" % oSystemInfo.uPageSize);
  oConsole.fOutput("    | Allocation granularity:  0x%X" % oSystemInfo.uAllocationAddressGranularity);
  oConsole.fOutput("    | System name:             %s" % oSystemInfo.sSystemName);
  oConsole.fOutput("    | System id:               %s" % oSystemInfo.sUniqueSystemId);
