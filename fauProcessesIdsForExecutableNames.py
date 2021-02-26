from .fdsGetProcessesExecutableName_by_uId import fdsGetProcessesExecutableName_by_uId;

def fauProcessesIdsForExecutableNames(asExecutableNames):
  asLoweredExecutableNames = [sExecutableName.lower() for sExecutableName in asExecutableNames];
  return [
    uId
    for (uId, sProcessExecutableName) in fdsGetProcessesExecutableName_by_uId().items()
    if sProcessExecutableName.lower() in asLoweredExecutableNames
  ];
