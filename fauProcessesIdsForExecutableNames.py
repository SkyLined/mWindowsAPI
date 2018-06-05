from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;

def fauProcessesIdsForExecutableNames(asExecutableNames):
  asLoweredExecutableNames = [sExecutableName.lower() for sExecutableName in asExecutableNames];
  return [
    uId
    for (uId, sProcessExecutableName) in fdsProcessesExecutableName_by_uId().items()
    if sProcessExecutableName.lower() in asLoweredExecutableNames
  ];
