import os, re;

from .cConsoleProcess import cConsoleProcess;

grGetAppxPackageOutputLine = re.compile(
  r"^"
  r"(.*?)"
  r"\s+:\s+"
  r"(.*?)"
  r"\s*$"
);

for sPath in os.get_exec_path():
  gsPowershellBinaryPath = os.path.join(sPath, "powershell.exe");
  if os.path.isfile(gsPowershellBinaryPath):
    break;
else:
  raise AssertionError("Cannot find powershell.exe!");

def fasRunPowershellAndGetStdOut(sPowershellCommand):
  global gsPowershellBinaryPath;
  oPowershellProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(gsPowershellBinaryPath, [sPowershellCommand]);
  oPowershellProcess.oStdInPipe.fClose(); # Prevent powershell from waiting for input for any reason.
  oPowershellProcess.fWait();
  sStdOut = oPowershellProcess.oStdOutPipe.fsRead();
  sStdErr = oPowershellProcess.oStdErrPipe.fsRead();
  assert oPowershellProcess.uExitCode == 0 and sStdErr == "", \
      "Powershell exited with error %d (stderr = %s, stdout = %s" % \
      (oPowershellProcess.uExitCode, repr(sStdErr), repr(sStdOut));
  asStdOut = sStdOut.split("\r\n");
  if asStdOut[-1] == "":
    asStdOut.pop();
  return asStdOut;

class cUWPApplication(object):
  def __init__(oSelf, sPackageName, sApplicationId = None):
    oSelf.sPackageName = sPackageName;
    
    # Find the package full name and family name
    asQueryOutput = fasRunPowershellAndGetStdOut("Get-AppxPackage %s" % oSelf.sPackageName);
    oSelf.sPackageFullName = None;
    oSelf.sPackageFamilyName = None;
    # Output should consist of "Name : Value" Pairs. Values can span multiple lines in which case additional lines
    # start with a number of spaces. There is never a space before a line that start with "Name :".
    # --- example multi-line output ---
    # Publisher         : CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, 
    #                     S=Washington, C=US
    # ---
    # Dependencies      : {Microsoft.NET.CoreRuntime.1.1_1.1.25915.0_x86__8wekyb3d8bbwe, 
    #                     Microsoft.VCLibs.140.00.Debug_14.0.26428.1_x86__8wekyb3d8bbwe}
    dsValue_by_sName = {};
    sCurrentName = None;
    uLines = 0;
    for sLine in asQueryOutput:
      if sLine:
        uLines += 1;
        if sLine[0] == " ":
          assert sCurrentName is not None, \
              "Get-AppxPackage output firstline starts with a space: %s in\r\n%s" % (repr(sLine), "\r\n".join(asQueryOutput));
          dsValue_by_sName[sCurrentName] += " " + sLine.strip();
        else:
          oNameAndValueMatch = re.match(grGetAppxPackageOutputLine, sLine);
          assert oNameAndValueMatch, \
              "Unrecognized Get-AppxPackage output: %s in\r\n%s" % (repr(sLine), "\r\n".join(asQueryOutput));
          sCurrentName, sValue = oNameAndValueMatch.groups();
          assert sCurrentName not in dsValue_by_sName, \
              "Get-AppxPackage output contains value for %s twice:\r\n%s" % (repr(sCurrentName), "\r\n".join(asQueryOutput));
          dsValue_by_sName[sCurrentName] = sValue;
    oSelf.bPackageExists = uLines > 0;
    if not oSelf.bPackageExists:
      oSelf.sPackageFullName = None;
      oSelf.sPackageFamilyName = None;
      oSelf.asApplicationIds = [];
    else:
      sNameValue = dsValue_by_sName.get("Name");
      assert sNameValue, \
          "Expected Get-AppxPackage output to contain 'Name' value.\r\n%s" % "\r\n".join(asQueryOutput);
      assert sNameValue.lower() == oSelf.sPackageName.lower(), \
          "Expected application package name to be %s, but got %s.\r\n%s" % \
          (oSelf.sPackageName, sNameValue, "\r\n".join(asQueryOutput));
      oSelf.sPackageFullName = dsValue_by_sName.get("PackageFullName");
      assert oSelf.sPackageFullName, \
          "Expected Get-AppxPackage output to contain 'PackageFullName' value.\r\n%s" % "\r\n".join(asQueryOutput);
      oSelf.sPackageFamilyName = dsValue_by_sName.get("PackageFamilyName");
      assert oSelf.sPackageFamilyName, \
          "Expected Get-AppxPackage output to contain 'PackageFamilyName' value.\r\n%s" % "\r\n".join(asQueryOutput);
      # Sanity check the application id
      oSelf.asApplicationIds = fasRunPowershellAndGetStdOut(
        "(Get-AppxPackageManifest %s).package.applications.application.id" % oSelf.sPackageFullName
      );
    if sApplicationId is None and len(oSelf.asApplicationIds) == 1:
      oSelf.sApplicationId = oSelf.asApplicationIds[0];
    else:
      oSelf.sApplicationId = sApplicationId;
    oSelf.bIdExists = oSelf.sApplicationId in oSelf.asApplicationIds;
