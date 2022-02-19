from .fds0GetProcessesExecutableName_by_uId import fds0GetProcessesExecutableName_by_uId;

def fauProcessesIdsForExecutableNames(asExecutableNames):
  asLoweredExecutableNames = [sExecutableName.lower() for sExecutableName in asExecutableNames];
  return [
    uId
    for (uId, s0ProcessExecutableName) in fds0GetProcessesExecutableName_by_uId().items()
    if s0ProcessExecutableName is not None and s0ProcessExecutableName.lower() in asLoweredExecutableNames
  ];
